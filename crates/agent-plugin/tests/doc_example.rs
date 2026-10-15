//! The exact manifest + script shape documented in `plugin-system.md`
//! §Hooks/"Writing one" — validated and run, so the doc cannot rot silently.

#[tokio::test]
async fn documented_hook_manifest_validates_and_runs() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = dir.path().join("git-guard");
    std::fs::create_dir_all(&plugin).unwrap();

    // A pure plugin — no `kind`, no `entry`: it never connects anywhere, the
    // hooks ARE the whole plugin.
    std::fs::write(
        plugin.join("manifest.json"),
        r#"{
  "id": "git-guard",
  "name": "Git Guard",
  "capabilities": {
    "hooks": [{
      "event": "before_tool_execute",
      "filter": { "tool": "bash" },
      "run": { "command": "./guard.sh" },
      "timeout_ms": 1000
    }]
  }
}"#,
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let script = plugin.join("guard.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\npayload=$(cat)\ncase \"$payload\" in\n  *\"push --force\"*) echo '{\"action\":\"veto\",\"reason\":\"force-push needs a human\"}';;\n  *)                echo '{\"action\":\"continue\"}';;\nesac\n",
        )
        .unwrap();
        let mut perm = std::fs::metadata(&script).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&script, perm).unwrap();
    }

    // Parse + validate the way `load_all` does.
    let text = std::fs::read_to_string(plugin.join("manifest.json")).unwrap();
    let mut manifest: agent_plugin::PluginManifest = serde_json::from_str(&text).unwrap();
    manifest.dir = plugin.clone();
    manifest
        .validate()
        .expect("the documented manifest must validate");

    let hooks = agent_plugin::hooks_from_manifest(&manifest, &[]);
    assert_eq!(hooks.len(), 1);
    let hook = &hooks[0];
    assert!(hook.matches("bash"));
    assert!(!hook.matches("read"));

    // The documented case table: a force-push is vetoed with its reason…
    match hook
        .run_before_tool(
            "bash",
            &serde_json::json!({"command": "git push --force origin main"}),
        )
        .await
    {
        agent_plugin::ToolVerdict::Veto(r) => assert_eq!(r, "force-push needs a human"),
        other => panic!("expected veto, got {other:?}"),
    }
    // …and everything else continues.
    assert!(matches!(
        hook.run_before_tool("bash", &serde_json::json!({"command": "ls"}))
            .await,
        agent_plugin::ToolVerdict::Continue
    ));
}
