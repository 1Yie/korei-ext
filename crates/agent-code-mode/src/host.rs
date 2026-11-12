use crate::{
    process::OwnedProcess,
    protocol::{self, bounded_json, Operation, ParentFrame, ToolRequest, WorkerFrame},
    types::check_bytes,
    CallSummary, CodeModeError, CodeModeRequest, CodeModeResponse, ErrorKind, ProcessEndpoint,
    ToolError,
};
use agent_tool::schema::{self, BoundedValidator};
use async_trait::async_trait;
use futures::{future::BoxFuture, stream::FuturesUnordered, Future, FutureExt, StreamExt};
use serde_json::Value;
use std::{collections::VecDeque, sync::Arc, time::Instant};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Host-owned capacity shared by every execution using the same handle.
/// A permit covers queued and running blocking work until it actually finishes.
#[derive(Clone)]
pub struct SchemaBudget(Arc<Semaphore>);

impl SchemaBudget {
    pub fn new(capacity: usize) -> Result<Self, CodeModeError> {
        if capacity == 0 || capacity > Semaphore::MAX_PERMITS {
            return Err(CodeModeError::new(
                ErrorKind::InvalidLimit,
                "invalid schema budget capacity",
            ));
        }
        Ok(Self(Arc::new(Semaphore::new(capacity))))
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, CodeModeError> {
        self.0
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| CodeModeError::new(ErrorKind::Cancelled, "schema budget closed"))
    }
}

/// Host authority boundary. Implementations must be cancellation-safe: dropping a
/// future stops local work; a dispatched external side effect may already have happened.
#[async_trait]
pub trait ToolBridge: Send + Sync {
    async fn list(&self, cursor: Value) -> Result<Value, ToolError>;
    /// Return registry data with `name`, `input_schema`, and optional `output_schema`.
    async fn describe(&self, name: &str) -> Result<Value, ToolError>;
    async fn call(&self, name: &str, args: Value) -> Result<Value, ToolError>;
}

fn schema_error(error: schema::ValidationError) -> ToolError {
    let kind = if matches!(error, schema::ValidationError::Limit(_)) {
        ErrorKind::Limit
    } else {
        ErrorKind::Tool
    };
    CodeModeError::new(kind, error.to_string())
}

enum InvocationValue {
    Complete(Value),
    DescribedCall {
        name: String,
        args: Value,
        description: Value,
    },
    UnvalidatedResult {
        result: Value,
        validator: BoundedValidator,
    },
    ValidatedCall {
        name: String,
        args: Value,
        output_validator: Option<BoundedValidator>,
    },
    ReadySchema {
        work: SchemaWork,
        permit: OwnedSemaphorePermit,
    },
}

enum SchemaWork {
    Prepare {
        name: String,
        args: Value,
        description: Value,
    },
    Validate {
        result: Value,
        validator: BoundedValidator,
    },
}

impl SchemaWork {
    fn run(self) -> Result<InvocationValue, CodeModeError> {
        match self {
            Self::Prepare {
                name,
                args,
                description,
            } => {
                let input = description.get("input_schema").ok_or_else(|| {
                    CodeModeError::new(
                        ErrorKind::Tool,
                        "registry description requires input_schema",
                    )
                })?;
                schema::validate(input, &args).map_err(schema_error)?;
                let output_validator = description
                    .get("output_schema")
                    .map(schema::validator)
                    .transpose()
                    .map_err(schema_error)?;
                Ok(InvocationValue::ValidatedCall {
                    name,
                    args,
                    output_validator,
                })
            }
            Self::Validate { result, validator } => {
                validator.validate(&result).map_err(schema_error)?;
                Ok(InvocationValue::Complete(result))
            }
        }
    }
}

async fn invoke(
    bridge: &dyn ToolBridge,
    operation: Operation,
    limit: usize,
) -> Result<InvocationValue, CodeModeError> {
    let value = match operation {
        Operation::List { cursor } => {
            bounded_json(&cursor, limit, "cursor")?;
            bridge.list(cursor).await?
        }
        Operation::Describe { name } => bridge.describe(&name).await?,
        Operation::Call { name, args } => {
            bounded_json(&args, limit, "tool arguments")?;
            let description = bridge.describe(&name).await?;
            bounded_json(&description, limit, "tool description")?;
            if description.get("name").and_then(Value::as_str) != Some(name.as_str()) {
                return Err(CodeModeError::new(
                    ErrorKind::Tool,
                    "registry description name mismatch",
                ));
            }
            return Ok(InvocationValue::DescribedCall {
                name,
                args,
                description,
            });
        }
    };
    bounded_json(&value, limit, "tool result")?;
    Ok(InvocationValue::Complete(value))
}

type InvocationResult = (u64, Result<InvocationValue, CodeModeError>, Instant);
type Invocation<'a> = BoxFuture<'a, InvocationResult>;

#[derive(Default)]
struct SchemaJobs(Option<tokio::task::JoinSet<InvocationResult>>);

impl SchemaJobs {
    async fn finish(&mut self) {
        if let Some(mut jobs) = self.0.take() {
            jobs.abort_all();
            // Running blocking jobs cannot be aborted. Retain ownership until
            // their helper-enforced finite work budget completes.
            while jobs.join_next().await.is_some() {}
        }
    }
}

impl Drop for SchemaJobs {
    fn drop(&mut self) {
        if let Some(mut jobs) = self.0.take() {
            jobs.abort_all();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { while jobs.join_next().await.is_some() {} });
            }
        }
    }
}

async fn run(
    pipes: (
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    ),
    request: &CodeModeRequest,
    bridge: &dyn ToolBridge,
    response: &mut CodeModeResponse,
    deadline: tokio::time::Instant,
    schema: (&mut tokio::task::JoinSet<InvocationResult>, &SchemaBudget),
) -> Result<Value, CodeModeError> {
    let (mut input, output, mut stderr) = pipes;
    let (schema_jobs, schema_budget) = schema;
    request.validate()?;
    let limits = &request.limits;
    let mut output = BufReader::new(output);
    let mut bytes = Vec::new();
    match protocol::read_async(&mut output, &mut bytes, limits.max_frame_bytes).await? {
        WorkerFrame::Ready { version: 1 } => {}
        _ => return Err(protocol::protocol("expected version 1 ready frame")),
    }
    // Metadata remains exclusively in the parent.
    let wire_request = CodeModeRequest {
        execution_id: request.execution_id.clone(),
        source: request.source.clone(),
        limits: request.limits.clone(),
        metadata: Value::Null,
    };
    protocol::write_async(
        &mut input,
        &ParentFrame::Start {
            version: 1,
            request: wire_request,
        },
        limits.max_frame_bytes,
    )
    .await?;
    let mut queue: VecDeque<ToolRequest> = VecDeque::new();
    let mut active: FuturesUnordered<Invocation<'_>> = FuturesUnordered::new();
    let mut next_id = 1;
    let mut pending = 0;
    let mut console_bytes = 0usize;
    let mut stderr_open = true;
    let mut stderr_buf = [0u8; 1024];
    loop {
        while active.len() + schema_jobs.len() < limits.max_concurrent {
            let Some(tool_request) = queue.pop_front() else {
                break;
            };
            active.push(
                async move {
                    let started = Instant::now();
                    let result = invoke(bridge, tool_request.operation, limits.max_result_bytes)
                        .await
                        .map_err(CodeModeError::bounded);
                    (tool_request.id, result, started)
                }
                .boxed(),
            );
        }
        tokio::select! {
            frame = protocol::read_async::<WorkerFrame>(&mut output, &mut bytes, limits.max_frame_bytes) => {
                match frame? {
                    WorkerFrame::Request { request: tool_request } => {
                        if tool_request.id != next_id {
                            return Err(protocol::protocol("request IDs must be unique and sequential from 1"));
                        }
                        if response.calls.len() >= limits.max_tool_calls || pending >= limits.max_pending {
                            return Err(CodeModeError::new(ErrorKind::Limit, "parent call or pending limit exceeded"));
                        }
                        if let Operation::Call { name, .. } | Operation::Describe { name } = &tool_request.operation {
                            if name.is_empty() || name.len() > 1024 { return Err(protocol::protocol("invalid tool name")); }
                        }
                        bounded_json(&tool_request.operation, limits.max_result_bytes, "tool request")?;
                        next_id += 1;
                        pending += 1;
                        let (operation, name) = tool_request.operation.summary();
                        response.calls.push(CallSummary {
                            id: tool_request.id,
                            operation: operation.into(),
                            name,
                            error: Some(CodeModeError::new(ErrorKind::Cancelled, "execution ended before this request completed")),
                            duration_ms: 0,
                        });
                        queue.push_back(tool_request);
                    }
                    WorkerFrame::Console { entry } => {
                        console_bytes = console_bytes.saturating_add(entry.text.len());
                        check_bytes("console", console_bytes, limits.max_console_bytes)?;
                        if response.console.len() >= limits.max_console_entries {
                            return Err(CodeModeError::new(ErrorKind::Limit, "parent console entry limit exceeded"));
                        }
                        response.console.push(entry);
                    }
                    WorkerFrame::Finish { result } => {
                        if let Ok(value) = &result { bounded_json(value, limits.max_output_bytes, "output")?; }
                        // Drop queued/active futures before observing process termination.
                        drop(active);
                        drop(queue);
                        drop(input);
                        let frame: Result<WorkerFrame, _> = protocol::read_async(&mut output, &mut bytes, limits.max_frame_bytes).await;
                        match frame {
                            Err(error) if error.message == "unexpected EOF" && bytes.is_empty() => {}
                            _ => return Err(protocol::protocol("data after finish frame")),
                        }
                        return result.map_err(CodeModeError::bounded);
                    }
                    WorkerFrame::Ready { .. } => return Err(protocol::protocol("duplicate ready frame")),
                }
            }
            event = async {
                tokio::select! {
                    Some(result) = active.next(), if !active.is_empty() => Ok(result),
                    Some(result) = schema_jobs.join_next(), if !schema_jobs.is_empty() =>
                        result.map_err(|error| CodeModeError::new(ErrorKind::Tool, error.to_string())),
                }
            }, if !active.is_empty() || !schema_jobs.is_empty() => {
                let (id, result, started) = event?;
                let mut result = match result {
                    Ok(value @ (InvocationValue::DescribedCall { .. } | InvocationValue::UnvalidatedResult { .. })) => {
                        let work = match value {
                            InvocationValue::DescribedCall { name, args, description } =>
                                SchemaWork::Prepare { name, args, description },
                            InvocationValue::UnvalidatedResult { result, validator } =>
                                SchemaWork::Validate { result, validator },
                            _ => unreachable!(),
                        };
                        active.push(async move {
                            let result = schema_budget.acquire().await
                                .map(|permit| InvocationValue::ReadySchema { work, permit });
                            (id, result, started)
                        }.boxed());
                        continue;
                    }
                    Ok(InvocationValue::ReadySchema { work, permit }) => {
                        schema_jobs.spawn_blocking(move || {
                            let _permit = permit;
                            let result = work.run().map_err(CodeModeError::bounded);
                            (id, result, started)
                        });
                        continue;
                    }
                    Ok(InvocationValue::ValidatedCall { name, args, output_validator }) => {
                        active.push(async move {
                            let result = async {
                                if tokio::time::Instant::now() >= deadline {
                                    return Err(CodeModeError::new(
                                        ErrorKind::Timeout,
                                        "parent execution deadline exceeded",
                                    ));
                                }
                                let result = bridge.call(&name, args).await?;
                                bounded_json(&result, limits.max_result_bytes, "tool result")?;
                                if let Some(validator) = output_validator {
                                    return Ok(InvocationValue::UnvalidatedResult { result, validator });
                                }
                                Ok(InvocationValue::Complete(result))
                            }.await.map_err(CodeModeError::bounded);
                            (id, result, started)
                        }.boxed());
                        // Yield from run itself: FuturesUnordered can repoll a
                        // yielding child before the outer execution guard runs.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Ok(InvocationValue::Complete(value)) => Ok(value),
                    Err(error) => Err(error),
                };
                let duration_ms = started.elapsed().as_millis() as u64;
                let mut frame = ParentFrame::Result { id, result: result.clone() };
                if let Err(error) = protocol::encode(&frame, limits.max_frame_bytes) {
                    result = Err(error);
                    frame = ParentFrame::Result { id, result: result.clone() };
                }
                let summary = &mut response.calls[(id - 1) as usize];
                summary.error = result.err();
                summary.duration_ms = duration_ms;
                pending -= 1;
                protocol::write_async(&mut input, &frame, limits.max_frame_bytes).await?;
            }
            count = stderr.read(&mut stderr_buf), if stderr_open => {
                let count = count.map_err(|e| protocol::protocol(e.to_string()))?;
                if count == 0 { stderr_open = false; }
                else {
                    // Diagnostics use framed console; arbitrary native stderr indicates a broken worker.
                    return Err(protocol::protocol("worker wrote unframed stderr"));
                }
            }
        }
    }
}

/// Run framed worker I/O alongside a continuously polled native supervisor.
/// Cancellation and deadline cover startup, schema preparation and stdout drain.
/// Drop cleanup requires the owning Tokio runtime to remain alive until reaping.
pub async fn execute(
    endpoint: ProcessEndpoint,
    request: CodeModeRequest,
    bridge: &dyn ToolBridge,
    schema_budget: SchemaBudget,
    cancellation: impl Future<Output = ()>,
) -> CodeModeResponse {
    let started = Instant::now();
    let mut response = CodeModeResponse {
        execution_id: request.execution_id.clone(),
        output: None,
        error: None,
        console: Vec::new(),
        calls: Vec::new(),
        duration_ms: 0,
    };
    let ProcessEndpoint {
        process,
        stdin,
        stdout,
        stderr,
    } = endpoint;
    let mut child = OwnedProcess(Some(process));
    let mut schema_jobs = SchemaJobs(Some(tokio::task::JoinSet::new()));
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(request.limits.deadline_ms.clamp(1, 30_000));
    let mut reaped = false;
    let mut result = {
        let execution = run(
            (stdin, stdout, stderr),
            &request,
            bridge,
            &mut response,
            deadline,
            (schema_jobs.0.as_mut().unwrap(), &schema_budget),
        );
        let supervision = async {
            let result = child.0.as_mut().unwrap().wait().await;
            reaped = result.is_ok();
            result
        };
        // try_join retains each future across wakeups: sampling clocks in wait
        // cannot be reset by unrelated protocol or tool activity.
        let supervised = async {
            let (value, ()) = futures::try_join!(execution, supervision)?;
            Ok(value)
        };
        tokio::select! {
            biased;
            _ = cancellation => Err(CodeModeError::new(ErrorKind::Cancelled, "execution cancelled")),
            _ = tokio::time::sleep_until(deadline) => Err(CodeModeError::new(ErrorKind::Timeout, "parent execution deadline exceeded")),
            result = supervised => result,
        }
    };
    if result
        .as_ref()
        .is_err_and(|e| e.kind == ErrorKind::Protocol && e.message == "unexpected EOF")
    {
        // EOF is the worker crash signal; explicit malformed frames remain protocol errors.
        result = Err(CodeModeError::new(
            ErrorKind::WorkerCrash,
            "worker closed stdout before finishing",
        ));
    }
    if !reaped {
        let process = child.0.as_mut().unwrap();
        let _ = process.start_kill();
        if let Err(error) = process.wait().await {
            // A killed child's exit error is expected; preserve the triggering
            // cancellation, protocol, VM or supervisor error.
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    schema_jobs.finish().await;
    child.0.take();
    match result {
        Ok(value) => response.output = Some(value),
        Err(error) => {
            if response.error.is_none() {
                response.error = Some(error);
            }
        }
    }
    response.duration_ms = started.elapsed().as_millis() as u64;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{oneshot, watch, Notify};

    struct TestProcess(watch::Receiver<bool>, watch::Sender<bool>);

    #[async_trait]
    impl crate::WorkerProcess for TestProcess {
        async fn wait(&mut self) -> Result<(), CodeModeError> {
            while !*self.0.borrow_and_update() {
                self.0.changed().await.map_err(|error| {
                    CodeModeError::new(ErrorKind::WorkerCrash, error.to_string())
                })?;
            }
            Ok(())
        }
        fn start_kill(&mut self) -> std::io::Result<()> {
            let _ = self.1.send(true);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestBridge {
        described: Notify,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ToolBridge for TestBridge {
        async fn list(&self, _: Value) -> Result<Value, ToolError> {
            unreachable!()
        }
        async fn describe(&self, name: &str) -> Result<Value, ToolError> {
            self.described.notify_one();
            Ok(serde_json::json!({"name":name,"input_schema":{},"output_schema":{}}))
        }
        async fn call(&self, _: &str, _: Value) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!(42))
        }
    }

    struct ExecutionFixture {
        task: tokio::task::JoinHandle<CodeModeResponse>,
        peer: tokio::task::JoinHandle<()>,
        cancel: oneshot::Sender<()>,
    }

    fn execution_fixture(budget: SchemaBudget, bridge: Arc<TestBridge>) -> ExecutionFixture {
        let (stdin, input) = tokio::io::duplex(8192);
        let (stdout, mut output) = tokio::io::duplex(8192);
        let (stderr, errors) = tokio::io::duplex(8192);
        let (exited, rx) = watch::channel(false);
        let endpoint = ProcessEndpoint {
            process: Box::new(TestProcess(rx, exited.clone())),
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
        };
        let peer = tokio::spawn(async move {
            let _errors = errors;
            let mut input = BufReader::new(input);
            let mut bytes = Vec::new();
            let limit = crate::types::HARD_FRAME_BYTES;
            protocol::write_async(&mut output, &WorkerFrame::Ready { version: 1 }, limit)
                .await
                .unwrap();
            let _: ParentFrame = protocol::read_async(&mut input, &mut bytes, limit)
                .await
                .unwrap();
            protocol::write_async(
                &mut output,
                &WorkerFrame::Request {
                    request: ToolRequest {
                        id: 1,
                        operation: Operation::Call {
                            name: "budgeted".into(),
                            args: Value::Null,
                        },
                    },
                },
                limit,
            )
            .await
            .unwrap();
            if let Ok(ParentFrame::Result { result, .. }) =
                protocol::read_async(&mut input, &mut bytes, limit).await
            {
                protocol::write_async(&mut output, &WorkerFrame::Finish { result }, limit)
                    .await
                    .unwrap();
            }
            drop(output);
            let _ = exited.send(true);
        });
        let (cancel, cancellation) = oneshot::channel();
        let task = tokio::spawn(async move {
            execute(
                endpoint,
                CodeModeRequest {
                    execution_id: "budget-fixture".into(),
                    source: "return 42".into(),
                    metadata: Value::Null,
                    limits: Default::default(),
                },
                bridge.as_ref(),
                budget,
                async {
                    let _ = cancellation.await;
                },
            )
            .await
        });
        ExecutionFixture { task, peer, cancel }
    }

    #[tokio::test]
    async fn shared_budget_survives_cancel_drop_and_deadline_before_later_execution() {
        for ending in ["cancel", "drop", "deadline"] {
            let budget = SchemaBudget::new(1).unwrap();
            let permit = budget.acquire().await.unwrap();
            let mut previous_jobs = SchemaJobs(Some(tokio::task::JoinSet::new()));
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            previous_jobs.0.as_mut().unwrap().spawn_blocking(move || {
                let _permit = permit;
                started_tx.send(()).unwrap();
                release_rx.blocking_recv().unwrap();
                (
                    1,
                    Ok(InvocationValue::Complete(Value::Null)),
                    Instant::now(),
                )
            });
            started_rx.await.unwrap();
            let bridge = Arc::new(TestBridge::default());
            let first = execution_fixture(budget.clone(), bridge.clone());
            bridge.described.notified().await;
            match ending {
                "cancel" => {
                    first.cancel.send(()).unwrap();
                    assert_eq!(
                        first.task.await.unwrap().error.unwrap().kind,
                        ErrorKind::Cancelled
                    );
                }
                "drop" => {
                    first.task.abort();
                    assert!(first.task.await.unwrap_err().is_cancelled());
                }
                _ => {
                    tokio::time::pause();
                    tokio::time::advance(std::time::Duration::from_secs(1)).await;
                    tokio::time::resume();
                    assert_eq!(
                        first.task.await.unwrap().error.unwrap().kind,
                        ErrorKind::Timeout
                    );
                }
            }
            first.peer.await.unwrap();
            assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
            drop(previous_jobs);
            assert!(budget.0.clone().try_acquire_owned().is_err());
            let next = execution_fixture(budget.clone(), bridge.clone());
            bridge.described.notified().await;
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            assert!(!next.task.is_finished());
            assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
            release_tx.send(()).unwrap();
            let response = next.task.await.unwrap();
            assert_eq!(response.output, Some(serde_json::json!(42)), "{response:?}");
            next.peer.await.unwrap();
            assert_eq!(bridge.calls.load(Ordering::SeqCst), 1);
            assert_eq!(budget.0.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn schema_cleanup_waits_for_running_bounded_work() {
        for drop_execution in [false, true] {
            let budget = SchemaBudget::new(1).unwrap();
            let permit = budget.acquire().await.unwrap();
            let mut jobs = SchemaJobs(Some(tokio::task::JoinSet::new()));
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
            jobs.0.as_mut().unwrap().spawn_blocking(move || {
                let _permit = permit;
                started_tx.send(()).unwrap();
                release_rx.blocking_recv().unwrap();
                finished_tx.send(()).unwrap();
                (
                    1,
                    Ok(InvocationValue::Complete(Value::Null)),
                    Instant::now(),
                )
            });
            started_rx.await.unwrap();
            assert_eq!(budget.0.available_permits(), 0);
            if drop_execution {
                drop(jobs);
                assert!(budget.0.clone().try_acquire_owned().is_err());
                release_tx.send(()).unwrap();
                finished_rx.await.unwrap();
            } else {
                let cleanup = tokio::spawn(async move { jobs.finish().await });
                tokio::task::yield_now().await;
                assert!(!cleanup.is_finished());
                assert!(budget.0.clone().try_acquire_owned().is_err());
                release_tx.send(()).unwrap();
                cleanup.await.unwrap();
                finished_rx.await.unwrap();
            }
            let returned = budget.acquire().await.unwrap();
            drop(returned);
            assert_eq!(budget.0.available_permits(), 1);
        }
    }

    #[test]
    fn queued_schema_abort_releases_permit_without_running_work() {
        assert!(SchemaBudget::new(0).is_err());
        assert!(SchemaBudget::new(Semaphore::MAX_PERMITS + 1).is_err());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let budget = SchemaBudget::new(1).unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.blocking_recv().unwrap();
            });
            started_rx.await.unwrap();
            let permit = budget.acquire().await.unwrap();
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let work_ran = ran.clone();
            let mut jobs = SchemaJobs(Some(tokio::task::JoinSet::new()));
            jobs.0.as_mut().unwrap().spawn_blocking(move || {
                let _permit = permit;
                work_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                (
                    1,
                    Ok(InvocationValue::Complete(Value::Null)),
                    Instant::now(),
                )
            });
            assert!(budget.0.clone().try_acquire_owned().is_err());
            jobs.0.as_mut().unwrap().abort_all();
            release_tx.send(()).unwrap();
            jobs.finish().await;
            blocker.await.unwrap();
            assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(budget.0.available_permits(), 1);
        });
    }
}
