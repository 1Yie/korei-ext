#![cfg(unix)]

use std::path::Path;

use agent_plugin::{McpClient, PluginManager, PluginManifest};
use serde_json::{json, Value};

fn server_manifest(dir: &Path, reply: Value) -> PluginManifest {
    let script = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *initialize*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id" ;;
    *tools/list*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"run","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *tools/call*)
      printf 'call\n' >> "$CALL_LOG"
      printf '{"jsonrpc":"2.0","id":%s,%s}\n' "$id" "$TOOL_REPLY" ;;
  esac
done
"#;
    let reply = serde_json::to_string(&reply).unwrap();
    let mut manifest: PluginManifest = serde_json::from_value(json!({
        "id": "fixture", "name": "fixture", "kind": "mcp",
        "entry": {
            "command": "/bin/sh", "args": ["-c", script],
            "env": {
                "TOOL_REPLY": &reply[1..reply.len() - 1],
                "CALL_LOG": dir.join("calls")
            }
        }
    }))
    .unwrap();
    manifest.dir = dir.to_path_buf();
    manifest
}

#[tokio::test]
async fn stdio_tool_results_preserve_error_status_and_text() {
    let cases = [
        (
            json!({"result": {"isError": true, "content": [
                {"type": "text", "text": "DATABASE_QUOTA_EXCEEDED"},
                {"type": "text", "text": "retry after 60s"}
            ]}}),
            Err("DATABASE_QUOTA_EXCEEDED\nretry after 60s\n"),
        ),
        (
            json!({"result": {"isError": true, "content": []}}),
            Err("MCP tool `run` failed without error content"),
        ),
        (
            json!({"result": {"isError": true, "content": [{"type": "text", "text": ""}]}}),
            Err("MCP tool `run` failed without error content"),
        ),
        (
            json!({"result": {"isError": false, "content": [
                {"type": "text", "text": "one"}, {"type": "text", "text": "two"}
            ]}}),
            Ok("one\ntwo\n"),
        ),
        (
            json!({"result": {"content": [{"type": "text", "text": "success"}]}}),
            Ok("success\n"),
        ),
        (json!({"result": {"content": []}}), Ok("")),
    ];
    for (reply, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let client = McpClient::start(&server_manifest(dir.path(), reply), "test", &[])
            .await
            .unwrap();
        let actual = client
            .call_tool("run", json!({}))
            .await
            .map_err(|error| error.to_string());
        assert_eq!(
            actual.as_ref().map(String::as_str).map_err(String::as_str),
            expected,
            "{actual:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("calls")).unwrap(),
            "call\n"
        );
    }
}

#[tokio::test]
async fn stdio_rpc_errors_preserve_the_server_message() {
    let dir = tempfile::tempdir().unwrap();
    let client = McpClient::start(
        &server_manifest(
            dir.path(),
            json!({"error": {"code": -32000, "message": "RPC_QUOTA_EXCEEDED"}}),
        ),
        "test",
        &[],
    )
    .await
    .unwrap();
    let error = client.call_tool("run", json!({})).await.unwrap_err();
    assert!(error.to_string().contains("RPC_QUOTA_EXCEEDED"), "{error}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("calls")).unwrap(),
        "call\n"
    );
}

#[tokio::test]
async fn manager_caps_success_application_errors_and_rpc_errors_at_the_same_utf8_budget() {
    const CAP: usize = 40 * 1024;
    let text = format!("quota: {}", "界".repeat(15_000));
    for reply in [
        json!({"result": {"content": [{"type": "text", "text": text}]}}),
        json!({"result": {"isError": true, "content": [{"type": "text", "text": text}]}}),
        json!({"error": {"code": -32000, "message": text}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let manifest = server_manifest(dir.path(), reply.clone());
        let paths =
            agent_paths::AppPaths::new(dir.path().join("config"), dir.path().join("data"), ".test");
        let mut manager = PluginManager::new(paths);
        manager.register_plugin(manifest, dir.path()).await.unwrap();
        let result = manager.dispatch_tool_call("fixture__run", json!({})).await;
        let is_error = reply.get("error").is_some() || reply["result"]["isError"] == true;
        assert_eq!(result.is_err(), is_error);
        let output = match result {
            Ok(output) | Err(output) => output,
        };
        let (body, suffix) = output
            .rsplit_once("\n… [truncated ")
            .expect("output is capped");
        assert!(body.len() <= CAP, "{} bytes", body.len());
        assert!(body.len() >= CAP - 3, "{} bytes", body.len());
        assert!(suffix.ends_with(" bytes]"), "{suffix:?}");
        assert!(output.len() < CAP + 64, "{} bytes", output.len());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("calls")).unwrap(),
            "call\n"
        );
    }
}
