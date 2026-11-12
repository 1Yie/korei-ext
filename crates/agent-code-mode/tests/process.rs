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
    async fn list(&self, _: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
        unreachable!()
    }
    async fn describe(&self, _: &BridgeRequestContext, _: &str) -> Result<Value, ToolError> {
        unreachable!()
    }
    async fn call(&self, _: &BridgeRequestContext, _: &str, _: Value) -> Result<Value, ToolError> {
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
        None,
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
        None,
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
        None,
        SchemaBudget::new(1).unwrap(),
        pending(),
    )
    .await;
    assert_eq!(response.error.unwrap().kind, ErrorKind::WorkerCrash);
    assert_eq!(state.waits.load(Ordering::SeqCst), 2);
    assert!(state.killed.load(Ordering::SeqCst));
    assert!(state.reaped.load(Ordering::SeqCst));
}

#[derive(Default)]
struct Trace {
    events: std::sync::Mutex<Vec<String>>,
    stops: std::sync::Mutex<Vec<ControllerStopCause>>,
    phases: std::sync::Mutex<Vec<(&'static str, BridgeRequestContext)>>,
    stopped: AtomicBool,
    dropped: AtomicUsize,
    active: Notify,
    queued: Notify,
}

impl ExecutionObserver for Trace {
    fn on_event(&self, event: ExecutionEvent<'_>) {
        let mut events = self.events.lock().unwrap();
        assert!(events.len() < 64);
        events.push(format!("{event:?}"));
        match event {
            ExecutionEvent::Stopping(cause) => {
                assert!(!self.stopped.swap(true, Ordering::SeqCst));
                self.stops.lock().unwrap().push(cause);
            }
            ExecutionEvent::RequestAccepted { context, .. } if context.request_id() == 2 => {
                self.queued.notify_one();
            }
            _ => {}
        }
    }
}

struct ObservedBridge<'a> {
    trace: &'a Trace,
    pending: bool,
}

struct BridgeWaiter<'a>(&'a Trace);

impl Drop for BridgeWaiter<'_> {
    fn drop(&mut self) {
        assert!(
            self.0.stopped.load(Ordering::SeqCst),
            "bridge dropped before Stopping"
        );
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl ToolBridge for ObservedBridge<'_> {
    async fn list(&self, context: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
        self.trace.phases.lock().unwrap().push(("list", *context));
        Ok(json!({"raw":"RAW_TOOL_SECRET".repeat(128)}))
    }

    async fn describe(
        &self,
        context: &BridgeRequestContext,
        name: &str,
    ) -> Result<Value, ToolError> {
        self.trace
            .phases
            .lock()
            .unwrap()
            .push(("describe", *context));
        Ok(json!({"name":name,"input_schema":{},"output_schema":{}}))
    }

    async fn call(
        &self,
        context: &BridgeRequestContext,
        _: &str,
        _: Value,
    ) -> Result<Value, ToolError> {
        self.trace.phases.lock().unwrap().push(("call", *context));
        if self.pending {
            let _waiter = BridgeWaiter(self.trace);
            self.trace.active.notify_one();
            pending().await
        } else {
            Ok(json!({"raw":"RAW_TOOL_SECRET".repeat(128)}))
        }
    }
}

#[tokio::test]
async fn observer_correlates_all_operations_without_raw_results_or_source() {
    let trace = Trace::default();
    let bridge = ObservedBridge {
        trace: &trace,
        pending: false,
    };
    let (endpoint, mut peer, _state) = endpoint();
    let peer = tokio::spawn(async move {
        ready(&mut peer).await;
        for (index, operation) in [
            json!({"op":"list","cursor":null}),
            json!({"op":"describe","name":"tool"}),
            json!({"op":"call","name":"tool","args":{}}),
        ]
        .into_iter()
        .enumerate()
        {
            frame(
                &mut peer.output,
                json!({"type":"request","request":{"id":index+1,"operation":operation}}),
            )
            .await;
            let mut line = String::new();
            peer.input.read_line(&mut line).await.unwrap();
            let result: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(result["id"], index + 1);
            assert!(result["result"].get("Ok").is_some());
        }
        frame(
            &mut peer.output,
            json!({"type":"console","entry":{"stream":"stdout","text":"bounded console"}}),
        )
        .await;
        frame(
            &mut peer.output,
            json!({"type":"finish","result":{"Ok":42}}),
        )
        .await;
        peer.output.shutdown().await.unwrap();
        peer.exits.send(Ok(())).unwrap();
    });
    let mut request = request();
    request.source = "return 'SOURCE_SECRET'".into();
    request.metadata = json!({"secret":"HOST_METADATA_SECRET"});
    let response = execute(
        endpoint,
        request,
        &bridge,
        Some(&trace),
        SchemaBudget::new(1).unwrap(),
        pending(),
    )
    .await;
    peer.await.unwrap();
    assert_eq!(response.output, Some(json!(42)), "{response:?}");
    let phases = trace.phases.lock().unwrap();
    assert_eq!(
        phases
            .iter()
            .map(|(phase, ctx)| (*phase, ctx.request_id(), ctx.operation()))
            .collect::<Vec<_>>(),
        vec![
            ("list", 1, BridgeOperation::List),
            ("describe", 2, BridgeOperation::Describe),
            ("describe", 3, BridgeOperation::Call),
            ("call", 3, BridgeOperation::Call),
        ]
    );
    assert_eq!(phases[2].1, phases[3].1);
    let events = trace.events.lock().unwrap();
    assert_eq!(events.first().unwrap(), "Started");
    assert_eq!(
        events
            .iter()
            .filter(|e| e.starts_with("RequestAccepted"))
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.starts_with("RequestCompleted"))
            .count(),
        3
    );
    assert_eq!(
        events.iter().filter(|e| e.starts_with("Console")).count(),
        1
    );
    let text = events.join("\n");
    for secret in ["RAW_TOOL_SECRET", "SOURCE_SECRET", "HOST_METADATA_SECRET"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert_eq!(
        *trace.stops.lock().unwrap(),
        [ControllerStopCause::GuestFinished]
    );
}

#[tokio::test]
async fn stopping_precedes_active_drop_on_every_controller_exit_and_guest_error() {
    for ending in [
        "finish",
        "vm-error",
        "guest-cancel",
        "guest-limit",
        "cancel",
        "deadline",
        "drop",
        "protocol",
        "process",
        "eof",
        "console-limit",
    ] {
        let trace = Trace::default();
        let bridge = ObservedBridge {
            trace: &trace,
            pending: true,
        };
        let (endpoint, mut peer, state) = endpoint();
        let peer_task = tokio::spawn(async move {
            ready(&mut peer).await;
            frame(&mut peer.output, json!({"type":"request","request":{"id":1,"operation":{"op":"call","name":"pending","args":{}}}})).await;
            peer
        });
        let (cancel, cancellation) = tokio::sync::oneshot::channel();
        let mut req = request();
        req.limits.max_concurrent = 1;
        req.limits.max_console_bytes = 16;
        let mut execution = Box::pin(execute(
            endpoint,
            req,
            &bridge,
            Some(&trace),
            SchemaBudget::new(1).unwrap(),
            async {
                let _ = cancellation.await;
            },
        ));
        tokio::select! {
            _ = trace.active.notified() => {}
            result = &mut execution => panic!("{ending}: unexpected result {result:?}"),
        }
        let mut peer = peer_task.await.unwrap();
        frame(
            &mut peer.output,
            json!({"type":"request","request":{"id":2,"operation":{"op":"list","cursor":null}}}),
        )
        .await;
        tokio::select! {
            _ = trace.queued.notified() => {}
            result = &mut execution => panic!("{ending}: unexpected result {result:?}"),
        }
        let expected = match ending {
            "finish" | "vm-error" | "guest-cancel" | "guest-limit" => {
                let result = match ending {
                    "finish" => json!({"Ok":42}),
                    _ => {
                        let kind = match ending {
                            "guest-cancel" => ErrorKind::Cancelled,
                            "guest-limit" => ErrorKind::Limit,
                            _ => ErrorKind::JsException,
                        };
                        json!({"Err":CodeModeError::new(kind, "guest-controlled")})
                    }
                };
                frame(&mut peer.output, json!({"type":"finish","result":result})).await;
                peer.output.shutdown().await.unwrap();
                peer.exits.send(Ok(())).unwrap();
                let response = (&mut execution).await;
                if ending == "finish" {
                    assert_eq!(response.output, Some(json!(42)));
                } else {
                    assert!(response.error.is_some());
                }
                drop(execution);
                ControllerStopCause::GuestFinished
            }
            "cancel" => {
                cancel.send(()).unwrap();
                assert_eq!(
                    (&mut execution).await.error.unwrap().kind,
                    ErrorKind::Cancelled
                );
                drop(execution);
                ControllerStopCause::ParentCancelled
            }
            "deadline" => {
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(2)).await;
                assert_eq!(
                    (&mut execution).await.error.unwrap().kind,
                    ErrorKind::Timeout
                );
                tokio::time::resume();
                drop(execution);
                ControllerStopCause::DeadlineExceeded
            }
            "drop" => {
                drop(execution);
                tokio::time::timeout(Duration::from_secs(1), state.reaped_signal.notified())
                    .await
                    .unwrap();
                ControllerStopCause::ExecuteDropped
            }
            _ => {
                let kind = match ending {
                    "protocol" => {
                        frame(&mut peer.output, json!({"type":"request","request":{"id":2,"operation":{"op":"list","cursor":null}}})).await;
                        ErrorKind::Protocol
                    }
                    "process" => {
                        peer.exits
                            .send(Err(CodeModeError::new(ErrorKind::Limit, "RSS exceeded")))
                            .unwrap();
                        ErrorKind::Limit
                    }
                    "console-limit" => {
                        frame(&mut peer.output, json!({"type":"console","entry":{"stream":"stdout","text":"x".repeat(17)}})).await;
                        ErrorKind::Limit
                    }
                    _ => {
                        peer.output.shutdown().await.unwrap();
                        ErrorKind::WorkerCrash
                    }
                };
                assert_eq!((&mut execution).await.error.unwrap().kind, kind);
                drop(execution);
                ControllerStopCause::ControllerFailed(kind)
            }
        };
        assert_eq!(*trace.stops.lock().unwrap(), [expected], "{ending}");
        assert_eq!(trace.dropped.load(Ordering::SeqCst), 1, "{ending}");
        assert_eq!(
            trace.phases.lock().unwrap().len(),
            2,
            "queued request dispatched: {ending}"
        );
        let events = trace.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("RequestAccepted"))
                .count(),
            2,
            "{ending}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("Console"))
                .count(),
            0,
            "{ending}"
        );
        assert!(state.reaped.load(Ordering::SeqCst), "{ending}");
    }
}

#[tokio::test]
async fn unpolled_execute_drop_stops_and_reaps_with_a_borrowed_observer() {
    let trace = Trace::default();
    let (endpoint, _peer, state) = endpoint();
    let execution = execute(
        endpoint,
        request(),
        &Bridge,
        Some(&trace),
        SchemaBudget::new(1).unwrap(),
        pending(),
    );
    drop(execution);
    assert_eq!(
        *trace.stops.lock().unwrap(),
        [ControllerStopCause::ExecuteDropped]
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        ["Started", "Stopping(ExecuteDropped)"]
    );
    tokio::time::timeout(Duration::from_secs(1), state.reaped_signal.notified())
        .await
        .unwrap();
    assert!(state.reaped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn supervisor_failure_stops_active_worker_and_preserves_kind() {
    let (endpoint, mut peer, state) = endpoint();
    let execution = tokio::spawn(execute(
        endpoint,
        request(),
        &Bridge,
        None,
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
        async fn list(&self, _: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
            unreachable!()
        }
        async fn describe(&self, _: &BridgeRequestContext, name: &str) -> Result<Value, ToolError> {
            Ok(json!({"name":name,"input_schema":{}}))
        }
        async fn call(
            &self,
            _: &BridgeRequestContext,
            _: &str,
            _: Value,
        ) -> Result<Value, ToolError> {
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
            None,
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
        None,
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
