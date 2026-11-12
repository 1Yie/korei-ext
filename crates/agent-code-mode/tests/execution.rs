use agent_code_mode::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::{
    future::pending,
    process::Stdio,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    sync::{oneshot, Notify},
};

#[tokio::test]
async fn guest_error_kind_cannot_claim_controller_cancellation() {
    #[derive(Default)]
    struct Stops(std::sync::Mutex<Vec<ControllerStopCause>>);
    impl ExecutionObserver for Stops {
        fn on_event(&self, event: ExecutionEvent<'_>) {
            if let ExecutionEvent::Stopping(cause) = event {
                self.0.lock().unwrap().push(cause);
            }
        }
    }
    for kind in ["cancelled", "limit", "timeout"] {
        let observer = Stops::default();
        let bridge = Mock::default();
        let child = Command::new(env!("CARGO_BIN_EXE_agent-code-mode-worker"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let response = execute(
            child.try_into().unwrap(),
            request(&format!("throw {{kind:'{kind}',message:'guest spoof'}};")),
            &bridge,
            Some(&observer),
            SchemaBudget::new(1).unwrap(),
            pending(),
        )
        .await;
        assert!(response.error.is_some(), "{response:?}");
        assert_eq!(
            *observer.0.lock().unwrap(),
            [ControllerStopCause::GuestFinished]
        );
    }
}

// Direct launch is an isolated VM/process experiment, not a production sandbox.
fn worker() -> Child {
    Command::new(env!("CARGO_BIN_EXE_agent-code-mode-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

#[derive(Default)]
struct Mock {
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    started: Notify,
}

struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl ToolBridge for Mock {
    async fn list(&self, _: &BridgeRequestContext, cursor: Value) -> Result<Value, ToolError> {
        Ok(if cursor.is_null() {
            json!({"tools":["mock.echo"], "cursor":1})
        } else {
            json!({"tools":["mock.fail"], "cursor":null})
        })
    }
    async fn describe(&self, _: &BridgeRequestContext, name: &str) -> Result<Value, ToolError> {
        if name == "mock.external" {
            return Ok(json!({"name":name,"input_schema":{"$ref":"file:///not-readable"}}));
        }
        if name == "mock.remote" {
            return Ok(
                json!({"name":name,"input_schema":{"$ref":"https://example.invalid/schema"}}),
            );
        }
        if name == "mock.bad-schema" {
            return Ok(json!({"name":name,"input_schema":{"type":7}}));
        }
        if name == "mock.missing-schema" {
            return Ok(json!({"name":name}));
        }
        if name == "mock.mismatched" {
            return Ok(json!({"name":"another-tool","input_schema":true}));
        }
        if name == "mock.local-ref" {
            return Ok(json!({"name":name,"input_schema":{
                "$defs":{"args":{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}},
                "$ref":"#/$defs/args"
            }}));
        }
        Ok(json!({
            "name":name,
            "input_schema":{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false},
            "output_schema":{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"],"additionalProperties":false}
        }))
    }
    async fn call(
        &self,
        _: &BridgeRequestContext,
        name: &str,
        args: Value,
    ) -> Result<Value, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(current, Ordering::SeqCst);
        let _active = Active(&self.active);
        self.started.notify_one();
        if name == "mock.pending" {
            pending::<()>().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        if name == "mock.fail" {
            Err(ToolError::new(ErrorKind::Tool, "mock failure"))
        } else if name == "mock.invalid" {
            Ok(json!("invalid result"))
        } else if name == "mock.large" {
            Ok(json!("x".repeat(2048)))
        } else {
            Ok(args)
        }
    }
}

fn request(source: &str) -> CodeModeRequest {
    CodeModeRequest {
        execution_id: "test-execution".into(),
        source: source.into(),
        metadata: json!({"authority":"parent only"}),
        limits: CodeModeLimits::default(),
    }
}

async fn evaluate(request: CodeModeRequest, bridge: &dyn ToolBridge) -> CodeModeResponse {
    tokio::time::timeout(
        Duration::from_secs(8),
        execute(
            worker().try_into().unwrap(),
            request,
            bridge,
            None,
            SchemaBudget::new(1).unwrap(),
            pending(),
        ),
    )
    .await
    .expect("controller exceeded test watchdog")
}

#[tokio::test]
async fn structured_async_registry_and_pagination() {
    let bridge = Mock::default();
    let response = evaluate(
        request(
            r#"
        const pages = [];
        let cursor = null;
        do {
            const page = await tools.list({cursor});
            pages.push(...page.tools);
            cursor = page.cursor;
        } while (cursor !== null);
        const description = await tools.describe(pages[0]);
        const result = await tools.call(description.name, {value:42});
        console.log("answer", result);
        console.error("diagnostic");
        return {pages, result};
    "#,
        ),
        &bridge,
    )
    .await;
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(
        response.output.unwrap(),
        json!({"pages":["mock.echo","mock.fail"],"result":{"value":42}})
    );
    assert_eq!(response.calls.len(), 4);
    assert_eq!(response.console.len(), 2);
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bridge_can_borrow_turn_owned_state() {
    struct Borrowed<'turn> {
        inner: &'turn Mock,
        policy: &'turn str,
    }
    #[async_trait]
    impl ToolBridge for Borrowed<'_> {
        async fn list(
            &self,
            context: &BridgeRequestContext,
            cursor: Value,
        ) -> Result<Value, ToolError> {
            let mut value = self.inner.list(context, cursor).await?;
            value["policy"] = json!(self.policy);
            Ok(value)
        }
        async fn describe(
            &self,
            context: &BridgeRequestContext,
            name: &str,
        ) -> Result<Value, ToolError> {
            self.inner.describe(context, name).await
        }
        async fn call(
            &self,
            context: &BridgeRequestContext,
            name: &str,
            args: Value,
        ) -> Result<Value, ToolError> {
            self.inner.call(context, name, args).await
        }
    }
    let inner = Mock::default();
    let policy = String::from("turn-owned-policy");
    let bridge = Borrowed {
        inner: &inner,
        policy: &policy,
    };
    let response = evaluate(
        request(
            r#"
        const page = await tools.list({cursor:null});
        const result = await tools.call("mock.echo",{value:1});
        return {policy:page.policy,result};
    "#,
        ),
        &bridge,
    )
    .await;
    assert_eq!(
        response.output,
        Some(json!({"policy":policy,"result":{"value":1}})),
        "{response:?}"
    );
}

#[tokio::test]
async fn bounded_parallel_and_independent_failures() {
    let bridge = Mock::default();
    let mut parallel = request(
        r#"
        return await Promise.all(Array.from({length:8}, (_, value) =>
            tools.call("mock.echo", {value})));
    "#,
    );
    parallel.limits.max_concurrent = 2;
    let response = evaluate(parallel, &bridge).await;
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.output.unwrap().as_array().unwrap().len(), 8);
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 8);
    assert_eq!(bridge.peak.load(Ordering::SeqCst), 2);
    let mut request = request(
        r#"
        return await Promise.allSettled(Array.from({length:8}, (_, value) =>
            tools.call(value === 3 ? "mock.fail" : "mock.echo", {value})));
    "#,
    );
    request.limits.max_concurrent = 2;
    let response = evaluate(request, &bridge).await;
    assert!(response.error.is_none(), "{response:?}");
    let output = response.output.unwrap();
    assert_eq!(output[3]["status"], "rejected");
    assert_eq!(output[2]["status"], "fulfilled");
    assert_eq!(response.calls.len(), 8);
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 16);
    assert_eq!(bridge.peak.load(Ordering::SeqCst), 2);
    assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn synchronous_and_async_exceptions_preserve_console_and_message() {
    for source in [
        "console.log('before failure'); throw new Error('specific failure')",
        "console.log('before failure'); return await Promise.reject(new Error('specific failure'))",
    ] {
        let bridge = Mock::default();
        let response = evaluate(request(source), &bridge).await;
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.kind, ErrorKind::JsException, "{response:?}");
        assert_eq!(error.message, "specific failure", "{response:?}");
        assert_eq!(response.console.len(), 1, "{response:?}");
        assert_eq!(response.console[0].text, "before failure");
        assert!(response.calls.is_empty(), "{response:?}");
        assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
    }
    let response = evaluate(request("throw null"), &Mock::default()).await;
    assert_eq!(response.error.unwrap().kind, ErrorKind::JsException);
}

#[tokio::test]
async fn caught_oom_cannot_dispatch_tools_and_memory_state_is_per_vm() {
    let bridge = Mock::default();
    let mut limited = request(
        r#"
        const values = [];
        try { while(true) values.push(new Array(10000).fill(42)); } catch (_) {}
        try { await tools.call("mock.echo", {value:1}); } catch (_) {}
        return 42;
    "#,
    );
    limited.limits.memory_bytes = 8 * 1024 * 1024;
    let response = evaluate(limited, &bridge).await;
    assert_eq!(
        response.error.as_ref().map(|e| e.kind),
        Some(ErrorKind::Limit),
        "{response:?}"
    );
    assert!(response.calls.is_empty(), "{response:?}");
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
    let response = evaluate(request("throw null"), &bridge).await;
    assert_eq!(response.error.unwrap().kind, ErrorKind::JsException);
    let response = evaluate(
        request("return await tools.call('mock.echo',{value:42})"),
        &bridge,
    )
    .await;
    assert_eq!(response.output, Some(json!({"value":42})), "{response:?}");
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn vm_resource_and_promise_matrix() {
    for (source, expected) in [
        ("while(true) {}", ErrorKind::Timeout),
        ("function f(){return 1+f()} return f()", ErrorKind::Limit),
        (
            "const a=[]; while(true) a.push(new Array(10000).fill(42))",
            ErrorKind::Limit,
        ),
        ("while(true) await Promise.resolve()", ErrorKind::Timeout),
        ("return await new Promise(() => {})", ErrorKind::JsException),
    ] {
        let bridge = Mock::default();
        let mut request = request(source);
        request.limits.deadline_ms = 500;
        request.limits.memory_bytes = 8 * 1024 * 1024;
        request.limits.stack_bytes = 128 * 1024;
        let response = evaluate(request, &bridge).await;
        assert_eq!(
            response.error.as_ref().map(|e| e.kind),
            Some(expected),
            "{source}: {response:?}"
        );
        assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn deadline_and_cancel_drop_active_bridge_and_reap_child() {
    for cancel in [false, true] {
        let bridge = Mock::default();
        let request = request("await tools.call('mock.pending', {value:1})");
        let deadline = Duration::from_millis(request.limits.deadline_ms);
        let child = worker();
        let pid = child.id().unwrap();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let execution = execute(
            child.try_into().unwrap(),
            request,
            &bridge,
            None,
            SchemaBudget::new(1).unwrap(),
            async {
                let _ = cancel_rx.await;
            },
        );
        tokio::pin!(execution);
        tokio::time::timeout(Duration::from_secs(8), async {
            tokio::select! {
                biased;
                _ = bridge.started.notified() => {}
                response = &mut execution => {
                    panic!("execution ended before bridge started: {response:?}");
                }
            }
        })
        .await
        .expect("bridge did not start before test watchdog");
        assert_eq!(bridge.active.load(Ordering::SeqCst), 1);
        if cancel {
            cancel_tx.send(()).unwrap();
        } else {
            // Keep real process startup outside the controlled-clock phase.
            tokio::time::pause();
            tokio::time::advance(deadline).await;
            tokio::time::resume();
        }
        let response = tokio::time::timeout(Duration::from_secs(3), &mut execution)
            .await
            .expect("controller failed to clean up active bridge");
        assert_eq!(
            response.error.as_ref().map(|e| e.kind),
            Some(if cancel {
                ErrorKind::Cancelled
            } else {
                ErrorKind::Timeout
            }),
            "{response:?}"
        );
        assert_eq!(bridge.calls.load(Ordering::SeqCst), 1, "{response:?}");
        assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
        assert_eq!(response.calls.len(), 1);
        assert_eq!(
            response.calls[0].error.as_ref().unwrap().kind,
            ErrorKind::Cancelled
        );
        #[cfg(unix)]
        assert!(!Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap()
            .success());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn startup_deadline_reaps_worker_before_any_bridge_dispatch() {
    let bridge = Mock::default();
    let child = Command::new("sh")
        .args(["-c", "exec sleep 30"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let mut request = request("return 42");
    request.limits.deadline_ms = 100;
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        execute(
            child.try_into().unwrap(),
            request,
            &bridge,
            None,
            SchemaBudget::new(1).unwrap(),
            pending(),
        ),
    )
    .await
    .expect("startup deadline failed to reap worker");
    assert_eq!(
        response.error.as_ref().map(|error| error.kind),
        Some(ErrorKind::Timeout),
        "{response:?}"
    );
    assert!(response.calls.is_empty(), "{response:?}");
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
    assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
    assert!(!Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap()
        .success());
}

#[tokio::test]
async fn invalidated_execution_prevents_validated_call_dispatch() {
    struct Described {
        described: Notify,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl ToolBridge for Described {
        async fn list(&self, _: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
            unreachable!()
        }
        async fn describe(&self, _: &BridgeRequestContext, name: &str) -> Result<Value, ToolError> {
            self.described.notify_one();
            Ok(json!({"name":name,"input_schema":{"type":"object"}}))
        }
        async fn call(
            &self,
            _: &BridgeRequestContext,
            _: &str,
            _: Value,
        ) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Null)
        }
    }
    for cancel in [false, true] {
        let bridge = Described {
            described: Notify::new(),
            calls: AtomicUsize::new(0),
        };
        let request = request("return await tools.call('mock.revoked', {})");
        let deadline = Duration::from_millis(request.limits.deadline_ms);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let execution = execute(
            worker().try_into().unwrap(),
            request,
            &bridge,
            None,
            SchemaBudget::new(1).unwrap(),
            async {
                let _ = cancel_rx.await;
            },
        );
        tokio::pin!(execution);
        tokio::time::timeout(Duration::from_secs(8), async {
            tokio::select! {
                biased;
                _ = bridge.described.notified() => {}
                response = &mut execution => {
                    panic!("execution ended before description: {response:?}");
                }
            }
        })
        .await
        .expect("description did not complete before test watchdog");
        if cancel {
            cancel_tx.send(()).unwrap();
        } else {
            tokio::time::pause();
            tokio::time::advance(deadline).await;
            tokio::time::resume();
        }
        let response = tokio::time::timeout(Duration::from_secs(3), &mut execution)
            .await
            .expect("invalidated execution did not stop");
        assert_eq!(
            response.error.as_ref().map(|error| error.kind),
            Some(if cancel {
                ErrorKind::Cancelled
            } else {
                ErrorKind::Timeout
            }),
            "{response:?}"
        );
        assert_eq!(bridge.calls.load(Ordering::SeqCst), 0, "{response:?}");
        assert_eq!(response.calls.len(), 1, "{response:?}");
    }
}

#[tokio::test]
async fn unawaited_work_is_discarded_and_completed_summaries_survive() {
    let bridge = Mock::default();
    let response = evaluate(
        request("tools.call('mock.echo', {value:1}); return 42"),
        &bridge,
    )
    .await;
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.output, Some(json!(42)));
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
    let response = evaluate(
        request(
            r#"
        await tools.call("mock.echo", {value:1});
        const pending = tools.call("mock.pending", {value:2});
        await tools.call("mock.echo", {value:3});
        return 42;
    "#,
        ),
        &bridge,
    )
    .await;
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.calls.len(), 3);
    assert!(response.calls[0].error.is_none());
    assert_eq!(
        response.calls[1].error.as_ref().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert!(response.calls[2].error.is_none());
    assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn limit_matrix_rejects_overflow_with_measured_byte_counts() {
    let mut cases = Vec::new();
    let mut source = request("return 42");
    source.limits.max_source_bytes = 1;
    cases.push((source, true));
    let mut frame = request(&format!("return '{}'", "x".repeat(8000)));
    frame.limits.max_frame_bytes = 4096;
    cases.push((frame, true));
    let mut console = request("console.log('abcdef'); return 1");
    console.limits.max_console_bytes = 3;
    cases.push((console, true));
    let mut output = request("return 'abcdefgh'");
    output.limits.max_output_bytes = 3;
    cases.push((output, true));
    let mut arguments = request("return await tools.call('mock.echo', {value:'x'.repeat(1000)})");
    arguments.limits.max_result_bytes = 512;
    cases.push((arguments, true));
    let mut result = request("return await tools.call('mock.large', {value:1})");
    result.limits.max_result_bytes = 512;
    cases.push((result, true));
    let mut entries = request("console.log(''); console.log(''); console.log('')");
    entries.limits.max_console_entries = 2;
    cases.push((entries, false));
    let mut flood = request("return await Promise.all(Array.from({length:3}, () => tools.call('mock.echo', {value:1})))");
    flood.limits.max_pending = 2;
    flood.limits.max_concurrent = 2;
    cases.push((flood, false));
    let mut calls = request("for(let i=0;i<3;i++) await tools.call('mock.echo', {value:i})");
    calls.limits.max_tool_calls = 2;
    calls.limits.max_pending = 2;
    calls.limits.max_concurrent = 2;
    cases.push((calls, false));
    for (request, measured) in cases {
        let bridge = Mock::default();
        let response = evaluate(request.clone(), &bridge).await;
        let error = response.error.as_ref().expect("limit accepted");
        assert_eq!(
            error.kind,
            ErrorKind::Limit,
            "{}: {response:?}",
            request.source
        );
        if measured {
            assert!(
                error.actual_bytes.unwrap() > error.limit_bytes.unwrap(),
                "{response:?}"
            );
        }
        assert!(bridge.peak.load(Ordering::SeqCst) <= request.limits.max_concurrent);
        assert!(bridge.calls.load(Ordering::SeqCst) <= request.limits.max_tool_calls);
        assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
    }

    struct ReturnedJson {
        value: Value,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl ToolBridge for ReturnedJson {
        async fn list(&self, _: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
            Ok(self.value.clone())
        }
        async fn describe(&self, _: &BridgeRequestContext, name: &str) -> Result<Value, ToolError> {
            let mut description = json!({"name":name,"input_schema":{},"output_schema":{}});
            if name == "mock.description" {
                description["notes"] = self.value.clone();
            }
            Ok(description)
        }
        async fn call(
            &self,
            _: &BridgeRequestContext,
            _: &str,
            _: Value,
        ) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.value.clone())
        }
    }
    let value = json!("\0\"\\\n汉🙂".repeat(16));
    let bridge = ReturnedJson {
        value: value.clone(),
        calls: AtomicUsize::new(0),
    };
    let description = json!({
        "name": "mock.description", "input_schema": {}, "output_schema": {}, "notes": value
    });
    assert!(value.as_str().unwrap().len() < 256);
    for (source, measured_value, output, rejected_calls, accepted_calls) in [
        (
            "return await tools.list()",
            value.clone(),
            value.clone(),
            0,
            0,
        ),
        (
            "return await tools.describe('mock.description')",
            description.clone(),
            description.clone(),
            0,
            0,
        ),
        (
            "return await tools.call('mock.description', {})",
            description,
            value.clone(),
            0,
            1,
        ),
        (
            "return await tools.call('mock.result', {})",
            value.clone(),
            value.clone(),
            1,
            1,
        ),
    ] {
        let actual = serde_json::to_vec(&measured_value).unwrap().len();
        assert!(actual > 256);
        for limit in [256, actual] {
            bridge.calls.store(0, Ordering::SeqCst);
            let mut request = request(source);
            request.limits.max_result_bytes = limit;
            let response = evaluate(request, &bridge).await;
            if limit < actual {
                let error = response.error.as_ref().unwrap();
                assert_eq!(error.kind, ErrorKind::Limit, "{source}: {response:?}");
                assert_eq!(error.actual_bytes, Some(actual), "{source}: {response:?}");
                assert_eq!(error.limit_bytes, Some(limit), "{source}: {response:?}");
                assert_eq!(bridge.calls.load(Ordering::SeqCst), rejected_calls);
            } else {
                assert!(response.error.is_none(), "{source}: {response:?}");
                assert_eq!(
                    response.output,
                    Some(output.clone()),
                    "{source}: {response:?}"
                );
                assert_eq!(bridge.calls.load(Ordering::SeqCst), accepted_calls);
            }
            assert_eq!(bridge.value, value);
        }
    }
}

#[tokio::test]
async fn invalid_limits_are_rejected_before_bridge_work() {
    let mut invalid = Vec::new();
    let defaults = CodeModeLimits::default();
    for stack_bytes in [0, 16 * 1024 * 1024 + 1] {
        invalid.push(CodeModeLimits {
            stack_bytes,
            ..defaults.clone()
        });
    }
    invalid.push(CodeModeLimits {
        max_concurrent: 17,
        ..defaults.clone()
    });
    invalid.push(CodeModeLimits {
        memory_bytes: 1,
        ..defaults.clone()
    });
    invalid.push(CodeModeLimits {
        deadline_ms: 30_001,
        ..defaults.clone()
    });
    invalid.push(CodeModeLimits {
        max_tool_calls: 0,
        ..defaults.clone()
    });
    invalid.push(CodeModeLimits {
        max_frame_bytes: usize::MAX,
        ..defaults.clone()
    });
    for limits in invalid {
        let bridge = Mock::default();
        let mut request = request("return 1");
        request.limits = limits;
        let response = evaluate(request, &bridge).await;
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            ErrorKind::InvalidLimit,
            "{response:?}"
        );
        assert_eq!(bridge.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn json_schema_and_tool_error_matrix() {
    let bridge = Mock::default();
    for source in [
        "return await tools.call('mock.echo', {value:'wrong'})",
        "return await tools.call('mock.invalid', {value:1})",
        "return await tools.call('mock.fail', {value:1})",
        "return await tools.call('mock.external', {value:1})",
        "return await tools.call('mock.remote', {value:1})",
        "return await tools.call('mock.bad-schema', {value:1})",
        "return await tools.call('mock.missing-schema', {value:1})",
        "return await tools.call('mock.mismatched', {value:1})",
    ] {
        let response = evaluate(request(source), &bridge).await;
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            ErrorKind::Tool,
            "{source}: {response:?}"
        );
        assert_eq!(
            response.calls[0].error.as_ref().unwrap().kind,
            ErrorKind::Tool
        );
    }
    for source in [
        "return 1n",
        "return {value:undefined}",
        "return NaN",
        "Number.isFinite=()=>true; return NaN",
        "const v={}; v.self=v; return v",
        "return await tools.call('mock.echo', {value:1n})",
        "return await tools.call('mock.echo', {value:()=>1})",
    ] {
        let response = evaluate(request(source), &bridge).await;
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            ErrorKind::JsException,
            "{source}: {response:?}"
        );
    }
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 2);
    let response = evaluate(
        request("return await tools.call('mock.local-ref', {value:1})"),
        &bridge,
    )
    .await;
    assert_eq!(response.output, Some(json!({"value":1})), "{response:?}");
}

#[tokio::test]
async fn host_apis_imports_metadata_and_execution_state_are_isolated() {
    let bridge = Mock::default();
    let response = evaluate(
        request(
            r#"
        return ["process","require","module","Buffer","fetch","WebSocket","Deno",
                "Bun","std","os","fs","env","metadata","__request"]
            .map(name => [name, typeof globalThis[name]]);
    "#,
        ),
        &bridge,
    )
    .await;
    assert!(response.error.is_none(), "{response:?}");
    for entry in response.output.unwrap().as_array().unwrap() {
        assert_eq!(entry[1], "undefined", "{entry}");
    }
    for source in [
        "return await import('node:fs')",
        "return await import('./local.js')",
        "return await import('https://example.invalid/module.js')",
        "return eval('42')",
        "return (0, eval)('42')",
        "return new Function('return 42')()",
        "return (()=>{}).constructor('return 42')()",
        "return (async()=>{}).constructor('return 42')()",
        "return (function*(){}).constructor('yield 42')().next()",
        "return (async function*(){}).constructor('yield 42')().next()",
        "return Object.getPrototypeOf(tools.call).constructor('return 42')()",
    ] {
        let response = evaluate(request(source), &bridge).await;
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            ErrorKind::JsException,
            "{response:?}"
        );
    }
    let response = evaluate(request("globalThis.secret=42; return secret"), &bridge).await;
    assert_eq!(response.output, Some(json!(42)));
    let response = evaluate(request("return typeof secret"), &bridge).await;
    assert_eq!(response.output, Some(json!("undefined")));
}

#[tokio::test]
async fn shared_schema_preparation_rejects_invalid_contracts_before_side_effects() {
    struct SchemaBridge {
        input: Value,
        output: Value,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl ToolBridge for SchemaBridge {
        async fn list(&self, _: &BridgeRequestContext, _: Value) -> Result<Value, ToolError> {
            unreachable!()
        }
        async fn describe(&self, _: &BridgeRequestContext, name: &str) -> Result<Value, ToolError> {
            Ok(json!({"name":name, "input_schema":self.input, "output_schema":self.output}))
        }
        async fn call(
            &self,
            _: &BridgeRequestContext,
            _: &str,
            args: Value,
        ) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(args)
        }
    }
    let mut defs = serde_json::Map::new();
    defs.insert("n0".into(), json!({"type":"object"}));
    for i in 1..16 {
        let reference = format!("#/$defs/n{}", i - 1);
        defs.insert(
            format!("n{i}"),
            json!({"allOf":[{"$ref":reference},{"$ref":reference}]}),
        );
    }
    for (schema, expected) in [
        (json!({"allOf":[{"$ref":"#"}]}), ErrorKind::Tool),
        (json!({"$dynamicRef":"#"}), ErrorKind::Tool),
        (
            json!({"$ref":"https://example.invalid/schema"}),
            ErrorKind::Tool,
        ),
        (json!({"$ref":"file:///private/schema"}), ErrorKind::Tool),
        (json!({"pattern":"(a+)+$"}), ErrorKind::Tool),
        (json!({"type":7}), ErrorKind::Tool),
        (json!({"$defs":defs,"$ref":"#/$defs/n15"}), ErrorKind::Limit),
    ] {
        for output in [false, true] {
            let bridge = SchemaBridge {
                input: if output { json!({}) } else { schema.clone() },
                output: if output { schema.clone() } else { json!({}) },
                calls: AtomicUsize::new(0),
            };
            let response =
                evaluate(request("return await tools.call('schema', {})"), &bridge).await;
            assert_eq!(
                response.error.as_ref().map(|error| error.kind),
                Some(expected),
                "{schema}: {response:?}"
            );
            assert_eq!(
                bridge.calls.load(Ordering::SeqCst),
                0,
                "{schema}: {response:?}"
            );
        }
    }
    let bridge = SchemaBridge {
        input: json!({"default":{"$ref":"file:///literal"}, "$defs":{"args":{"type":"object"}},"$ref":"#/$defs/args"}),
        output: json!({"type":"object"}),
        calls: AtomicUsize::new(0),
    };
    let response = evaluate(request("return await tools.call('schema', {})"), &bridge).await;
    assert_eq!(response.output, Some(json!({})), "{response:?}");
    assert_eq!(bridge.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dead_worker_is_contained() {
    let mut child = worker();
    child.start_kill().unwrap();
    let response = execute(
        child.try_into().unwrap(),
        request("return 42"),
        &Mock::default(),
        None,
        SchemaBudget::new(1).unwrap(),
        pending(),
    )
    .await;
    assert_eq!(
        response.error.as_ref().unwrap().kind,
        ErrorKind::WorkerCrash,
        "{response:?}"
    );
    let response = evaluate(request("return 42"), &Mock::default()).await;
    assert_eq!(response.output, Some(json!(42)));
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_controller_kills_and_reaps_worker() {
    use std::sync::Arc;
    let bridge = Arc::new(Mock::default());
    let child = worker();
    let pid = child.id().unwrap();
    let owned_bridge = bridge.clone();
    let task = tokio::spawn(async move {
        execute(
            child.try_into().unwrap(),
            request("await tools.call('mock.pending',{value:1})"),
            owned_bridge.as_ref(),
            None,
            SchemaBudget::new(1).unwrap(),
            pending(),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while bridge.active.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(bridge.active.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(2), async {
        while Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap()
            .success()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropped controller left its child alive");
}
