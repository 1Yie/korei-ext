use agent_code_mode::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::{
    future::pending,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    sync::{mpsc, Notify},
};

#[derive(Default)]
struct State {
    waits: AtomicUsize,
    samples: AtomicUsize,
    killed: AtomicBool,
    reaped: AtomicBool,
    reaped_signal: Notify,
}

struct Process {
    state: Arc<State>,
    rx: mpsc::UnboundedReceiver<Result<(), CodeModeError>>,
    tx: mpsc::UnboundedSender<Result<(), CodeModeError>>,
}

#[async_trait]
impl WorkerProcess for Process {
    async fn wait(&mut self) -> Result<(), CodeModeError> {
        self.state.waits.fetch_add(1, Ordering::SeqCst);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    assert!(!self.state.reaped.load(Ordering::SeqCst));
                    self.state.samples.fetch_add(1, Ordering::SeqCst);
                }
                result = self.rx.recv() => {
                    self.state.reaped.store(true, Ordering::SeqCst);
                    self.state.reaped_signal.notify_one();
                    return result.unwrap();
                }
            }
        }
    }

    fn start_kill(&mut self) -> std::io::Result<()> {
        self.state.killed.store(true, Ordering::SeqCst);
        let _ = self.tx.send(Ok(()));
        Ok(())
    }
}

struct Bridge;

#[async_trait]
impl ToolBridge for Bridge {
    async fn list(&self, _: Value) -> Result<Value, ToolError> {
        unreachable!()
    }
    async fn describe(&self, _: &str) -> Result<Value, ToolError> {
        unreachable!()
    }
    async fn call(&self, _: &str, _: Value) -> Result<Value, ToolError> {
        unreachable!()
    }
}

struct Peer {
    input: BufReader<DuplexStream>,
    output: DuplexStream,
    stderr: DuplexStream,
    exits: mpsc::UnboundedSender<Result<(), CodeModeError>>,
}

fn endpoint() -> (ProcessEndpoint, Peer, Arc<State>) {
    let (stdin, input) = tokio::io::duplex(8192);
    let (stdout, output) = tokio::io::duplex(8192);
    let (stderr, errors) = tokio::io::duplex(8192);
    let (tx, rx) = mpsc::unbounded_channel();
    let state = Arc::new(State::default());
    (
        ProcessEndpoint {
            process: Box::new(Process {
                state: state.clone(),
                rx,
                tx: tx.clone(),
            }),
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
        },
        Peer {
            input: BufReader::new(input),
            output,
            stderr: errors,
            exits: tx,
        },
        state,
    )
}

fn request() -> CodeModeRequest {
    CodeModeRequest {
        execution_id: "fake-supervisor".into(),
        source: "return 42".into(),
        metadata: Value::Null,
        limits: CodeModeLimits::default(),
    }
}

async fn frame(output: &mut DuplexStream, value: Value) {
    output
        .write_all(format!("{value}\n").as_bytes())
        .await
        .unwrap();
}

async fn ready(peer: &mut Peer) {
    frame(&mut peer.output, json!({"type":"ready","version":1})).await;
    let mut line = String::new();
    peer.input.read_line(&mut line).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["type"],
        "start"
    );
}

#[tokio::test(start_paused = true)]
async fn supervisor_is_pinned_and_sampled_during_busy_worker_io() {
    let (endpoint, mut peer, state) = endpoint();
    let execution = tokio::spawn(execute(
        endpoint,
        request(),
        &Bridge,
        SchemaBudget::new(1).unwrap(),
        pending(),
    ));
    ready(&mut peer).await;
    for _ in 0..15 {
        frame(
            &mut peer.output,
            json!({"type":"console","entry":{"stream":"stdout","text":"active"}}),
        )
        .await;
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    assert!(state.samples.load(Ordering::SeqCst) >= 2);
    assert_eq!(state.waits.load(Ordering::SeqCst), 1);
    assert!(!execution.is_finished());
    frame(
        &mut peer.output,
        json!({"type":"finish","result":{"Ok":42}}),
    )
    .await;
    drop(peer.output);
    drop(peer.stderr);
    peer.exits.send(Ok(())).unwrap();
    let response = execution.await.unwrap();
    assert_eq!(response.output, Some(json!(42)), "{response:?}");
    assert_eq!(response.console.len(), 15);
    assert!(state.reaped.load(Ordering::SeqCst));
    assert!(!state.killed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn successful_exit_before_stdout_finish_is_drained() {
    let (endpoint, mut peer, state) = endpoint();
    let execution = tokio::spawn(execute(
        endpoint,
        request(),
        &Bridge,
        SchemaBudget::new(1).unwrap(),
        pending(),
    ));
    ready(&mut peer).await;
    peer.exits.send(Ok(())).unwrap();
    state.reaped_signal.notified().await;
    assert!(!execution.is_finished());
    frame(
        &mut peer.output,
        json!({"type":"finish","result":{"Ok":42}}),
    )
    .await;
    drop(peer.output);
    drop(peer.stderr);
    let response = execution.await.unwrap();
    assert_eq!(response.output, Some(json!(42)), "{response:?}");
    assert_eq!(state.waits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_supervision_still_kills_and_reaps_unexited_child() {
    struct FailedWait(Arc<State>);
    #[async_trait]
    impl WorkerProcess for FailedWait {
        async fn wait(&mut self) -> Result<(), CodeModeError> {
            if self.0.waits.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(CodeModeError::new(ErrorKind::WorkerCrash, "wait failed"));
            }
            assert!(self.0.killed.load(Ordering::SeqCst));
            self.0.reaped.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn start_kill(&mut self) -> std::io::Result<()> {
            self.0.killed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    let (mut endpoint, _peer, state) = endpoint();
    endpoint.process = Box::new(FailedWait(state.clone()));
    let response = execute(
        endpoint,
        request(),
        &Bridge,
        SchemaBudget::new(1).unwrap(),
        pending(),
    )
    .await;
    assert_eq!(response.error.unwrap().kind, ErrorKind::WorkerCrash);
    assert_eq!(state.waits.load(Ordering::SeqCst), 2);
    assert!(state.killed.load(Ordering::SeqCst));
    assert!(state.reaped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn supervisor_failure_stops_active_worker_and_preserves_kind() {
    let (endpoint, mut peer, state) = endpoint();
    let execution = tokio::spawn(execute(
        endpoint,
        request(),
        &Bridge,
        SchemaBudget::new(1).unwrap(),
        pending(),
    ));
    ready(&mut peer).await;
    peer.exits
        .send(Err(CodeModeError::new(ErrorKind::Limit, "RSS exceeded")))
        .unwrap();
    let response = execution.await.unwrap();
    assert_eq!(response.error.unwrap().kind, ErrorKind::Limit);
    assert!(response.calls.is_empty());
    assert!(state.reaped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn supervisor_runs_during_pending_callback_and_cancellation_reaps() {
    struct PendingBridge(Notify);
    #[async_trait]
    impl ToolBridge for PendingBridge {
        async fn list(&self, _: Value) -> Result<Value, ToolError> {
            unreachable!()
        }
        async fn describe(&self, name: &str) -> Result<Value, ToolError> {
            Ok(json!({"name":name,"input_schema":{}}))
        }
        async fn call(&self, _: &str, _: Value) -> Result<Value, ToolError> {
            self.0.notify_one();
            pending().await
        }
    }
    let (endpoint, mut peer, state) = endpoint();
    let bridge = Arc::new(PendingBridge(Notify::new()));
    let owned_bridge = bridge.clone();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let execution = tokio::spawn(async move {
        execute(
            endpoint,
            request(),
            owned_bridge.as_ref(),
            SchemaBudget::new(1).unwrap(),
            async {
                let _ = cancel_rx.await;
            },
        )
        .await
    });
    ready(&mut peer).await;
    frame(
        &mut peer.output,
        json!({"type":"request","request":{
            "id":1,"operation":{"op":"call","name":"pending","args":{}}
        }}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), bridge.0.notified())
        .await
        .unwrap();
    let before = state.samples.load(Ordering::SeqCst);
    tokio::time::pause();
    for _ in 0..10 {
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    tokio::time::resume();
    assert!(state.samples.load(Ordering::SeqCst) > before);
    assert_eq!(state.waits.load(Ordering::SeqCst), 1);
    assert!(!execution.is_finished());
    cancel_tx.send(()).unwrap();
    let response = execution.await.unwrap();
    assert_eq!(response.error.unwrap().kind, ErrorKind::Cancelled);
    assert!(state.killed.load(Ordering::SeqCst));
    assert!(state.reaped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn dropping_endpoint_execution_kills_and_reaps_entire_adapter() {
    let (endpoint, mut peer, state) = endpoint();
    let execution = tokio::spawn(execute(
        endpoint,
        request(),
        &Bridge,
        SchemaBudget::new(1).unwrap(),
        pending(),
    ));
    ready(&mut peer).await;
    execution.abort();
    assert!(execution.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), state.reaped_signal.notified())
        .await
        .unwrap();
    assert!(state.killed.load(Ordering::SeqCst));
    assert!(state.reaped.load(Ordering::SeqCst));
}
