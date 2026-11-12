use agent_code_mode::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::{future::pending, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

fn worker() -> Child {
    Command::new(env!("CARGO_BIN_EXE_agent-code-mode-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

fn request(source: &str) -> CodeModeRequest {
    CodeModeRequest {
        execution_id: "protocol-test".into(),
        source: source.into(),
        limits: CodeModeLimits {
            max_frame_bytes: 4096,
            ..Default::default()
        },
        metadata: Value::Null,
    }
}

#[tokio::test]
async fn worker_rejects_invalid_or_duplicate_results_and_oversized_frames() {
    for bad in [
        r#"{"type":"result","id":99,"result":{"Ok":42}}"#.to_string(),
        r#"{"type":"start","version":1,"request":{}}"#.to_string(),
        r#"{"type":"result","id":1,"result":{"Ok":42},"extra":1}"#.to_string(),
        r#"{"type":"result","id":1,"result":{"Ok":42,"Err":{}}}"#.to_string(),
        "x".repeat(5000),
        "duplicate".to_string(),
    ] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut child = worker();
            let mut input = child.stdin.take().unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            assert_eq!(
                serde_json::from_str::<Value>(&lines.next_line().await.unwrap().unwrap()).unwrap()
                    ["type"],
                "ready"
            );
            let start = json!({"type":"start","version":1,"request":request(
                "return await Promise.all([tools.call('one', {}),tools.call('two', {})])"
            )});
            input
                .write_all(format!("{start}\n").as_bytes())
                .await
                .unwrap();
            for _ in 0..2 {
                let line = lines.next_line().await.unwrap().unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap()["type"],
                    "request"
                );
            }
            if bad == "duplicate" {
                input
                    .write_all(b"{\"type\":\"result\",\"id\":1,\"result\":{\"Ok\":42}}\n")
                    .await
                    .unwrap();
                input
                    .write_all(b"{\"type\":\"result\",\"id\":1,\"result\":{\"Ok\":42}}\n")
                    .await
                    .unwrap();
            } else {
                input
                    .write_all(format!("{bad}\n").as_bytes())
                    .await
                    .unwrap();
            }
            let line = lines.next_line().await.unwrap().unwrap();
            let frame: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(frame["type"], "finish", "{frame}");
            assert_eq!(
                frame["result"]["Err"]["kind"],
                if bad.len() > 4096 {
                    "limit"
                } else {
                    "protocol"
                },
                "{frame}"
            );
            drop(input);
            assert!(child.wait().await.unwrap().success());
        })
        .await
        .expect("raw worker protocol test hung");
    }
}

#[tokio::test]
async fn worker_accepts_out_of_order_completion_for_known_ids() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut child = worker();
        let mut input = child.stdin.take().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        lines.next_line().await.unwrap().unwrap();
        let start = json!({"type":"start","version":1,"request":request(
            "return await Promise.all([tools.call('one', {}),tools.call('two', {})])"
        )});
        input
            .write_all(format!("{start}\n").as_bytes())
            .await
            .unwrap();
        for _ in 0..2 {
            lines.next_line().await.unwrap().unwrap();
        }
        for id in [2, 1] {
            let frame = json!({"type":"result","id":id,"result":{"Ok":id}});
            input
                .write_all(format!("{frame}\n").as_bytes())
                .await
                .unwrap();
        }
        let frame: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(frame["result"]["Ok"], json!([1, 2]), "{frame}");
        drop(input);
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn worker_preserves_every_bridge_error_kind_and_byte_metadata() {
    for kind in [
        ErrorKind::InvalidLimit,
        ErrorKind::JsException,
        ErrorKind::Limit,
        ErrorKind::Timeout,
        ErrorKind::Cancelled,
        ErrorKind::Protocol,
        ErrorKind::Tool,
        ErrorKind::WorkerCrash,
    ] {
        for caught in [false, true] {
            tokio::time::timeout(Duration::from_secs(8), async {
                let mut child = worker();
                let mut input = child.stdin.take().unwrap();
                let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
                let ready: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                assert_eq!(ready["type"], "ready");
                let source = if caught {
                    "try { return await tools.call('mock', {}); } catch (error) {
                        return {kind:error.kind, message:error.message,
                            actual_bytes:error.actual_bytes, limit_bytes:error.limit_bytes};
                    }"
                } else {
                    "return await tools.call('mock', {})"
                };
                let start = json!({"type":"start","version":1,"request":request(source)});
                input
                    .write_all(format!("{start}\n").as_bytes())
                    .await
                    .unwrap();
                let call: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                assert_eq!(call["type"], "request", "{call}");
                let mut error = CodeModeError::new(kind, "bridge rejected request");
                error.actual_bytes = Some(1234);
                error.limit_bytes = Some(1024);
                let expected = serde_json::to_value(error).unwrap();
                let result =
                    json!({"type":"result","id":call["request"]["id"],"result":{"Err":expected}});
                input
                    .write_all(format!("{result}\n").as_bytes())
                    .await
                    .unwrap();
                let finish: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                assert_eq!(finish["type"], "finish", "{finish}");
                assert_eq!(
                    finish["result"][if caught { "Ok" } else { "Err" }],
                    expected,
                    "kind={kind:?}, caught={caught}: {finish}"
                );
                drop(input);
                assert!(child.wait().await.unwrap().success());
            })
            .await
            .expect("bridge error matrix hung");
        }
    }
}

#[tokio::test]
async fn vm_interrupt_reports_timeout_without_parent_controller() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut child = worker();
        let mut input = child.stdin.take().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        lines.next_line().await.unwrap().unwrap();
        let mut request = request("while(true) {}");
        request.limits.deadline_ms = 100;
        let start = json!({"type":"start","version":1,"request":request});
        input
            .write_all(format!("{start}\n").as_bytes())
            .await
            .unwrap();
        let frame: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(frame["result"]["Err"]["kind"], "timeout", "{frame}");
        drop(input);
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .expect("VM's own CPU interrupt failed");
}

struct Never;
#[async_trait]
impl ToolBridge for Never {
    async fn list(&self, _: Value) -> Result<Value, ToolError> {
        pending().await
    }
    async fn describe(&self, _: &str) -> Result<Value, ToolError> {
        pending().await
    }
    async fn call(&self, _: &str, _: Value) -> Result<Value, ToolError> {
        pending().await
    }
}

#[cfg(unix)]
#[tokio::test]
async fn parent_rejects_malformed_duplicate_out_of_order_and_excess_messages() {
    let ready = json!({"type":"ready","version":1}).to_string();
    let tool = |id| {
        json!({"type":"request","request":{"id":id,"operation":{"op":"list","cursor":null}}})
            .to_string()
    };
    let finish = json!({"type":"finish","result":{"Ok":42}}).to_string();
    let mut cases = vec![
        (
            json!({"type":"ready","version":2}).to_string(),
            vec![],
            ErrorKind::Protocol,
        ),
        (ready.clone(), vec!["{broken".into()], ErrorKind::Protocol),
        (ready.clone(), vec![ready.clone()], ErrorKind::Protocol),
        (ready.clone(), vec![tool(2)], ErrorKind::Protocol),
        (ready.clone(), vec![tool(1), tool(1)], ErrorKind::Protocol),
        (
            ready.clone(),
            vec![tool(1), tool(2), tool(3)],
            ErrorKind::Limit,
        ),
        (ready.clone(), vec!["x".repeat(5000)], ErrorKind::Limit),
        (
            ready.clone(),
            vec![finish.clone(), finish],
            ErrorKind::Protocol,
        ),
        (ready.clone(), vec![], ErrorKind::WorkerCrash),
    ];
    for (initial, frames, expected) in cases.drain(..) {
        // Fixed, test-owned JSON only; no source or registry input reaches the shell.
        let mut script = format!("printf '%s\\n' '{initial}'; IFS= read -r ignored;");
        for frame in frames {
            script.push_str(&format!("printf '%s\\n' '{frame}';"));
        }
        let child = Command::new("sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut request = request("return 42");
        request.limits.max_pending = 2;
        request.limits.max_concurrent = 1;
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            execute(
                child.try_into().unwrap(),
                request,
                &Never,
                SchemaBudget::new(1).unwrap(),
                pending(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            expected,
            "{script}: {response:?}"
        );
    }
}
