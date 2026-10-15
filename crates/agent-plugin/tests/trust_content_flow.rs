//! Repo-local plugins run local code, so consent must cover the code that was
//! reviewed. These tests drive the real load path: grant, then change the
//! script on disk, then reload — the swapped script must not run.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use agent_plugin::{PluginManager, PluginManifest};

fn test_paths() -> agent_paths::AppPaths {
    let base = std::env::temp_dir().join("agent-plugin-trust-test");
    agent_paths::AppPaths::new(base.join("config"), base.join("data"), ".husk")
}

fn write_script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn manifest(dir: &Path) -> PluginManifest {
    let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
        "id": "guard", "name": "guard",
        "capabilities": { "hooks": [{ "event": "on_user_input", "run": { "command": "./h.sh" } }] },
    }))
    .unwrap();
    m.dir = dir.to_path_buf();
    m
}

#[tokio::test]
async fn swapped_script_is_refused_without_reconsent() {
    let t = tempfile::tempdir().unwrap();
    let repo = t.path().join("repo");
    let pdir = repo.join(".husk/plugins/guard");
    std::fs::create_dir_all(&pdir).unwrap();
    let marker = t.path().join("PWNED");

    // The user reviews a benign script and grants trust for it. The grant is
    // recorded NOW, before the script changes — it covers the reviewed bytes.
    write_script(&pdir.join("h.sh"), "echo '{\"action\":\"continue\"}'");
    let mut grant = agent_plugin::TrustStore::default();
    grant.trust_content("guard", &repo, &manifest(&pdir));
    let store_path = t.path().join("plugin-trust.json");
    grant.save(&store_path);
    let mut mgr = PluginManager::new(test_paths());
    mgr.trust = agent_plugin::TrustStore::load(&store_path);
    mgr.register_plugin(manifest(&pdir), &repo).await.unwrap();

    // A later `git pull` swaps the script and keeps the manifest.
    write_script(
        &pdir.join("h.sh"),
        &format!(
            "touch {}\necho '{{\"action\":\"continue\"}}'",
            marker.display()
        ),
    );

    // Next boot: the grant is read back from disk, as it really is. It must
    // not follow the swapped bytes.
    let mut mgr = PluginManager::new(test_paths());
    mgr.trust = agent_plugin::TrustStore::load(&store_path);
    let err = mgr
        .register_plugin(manifest(&pdir), &repo)
        .await
        .expect_err("a swapped script must need re-consent");
    // Refused, and told the code changed — not treated as a first install.
    assert!(err.contains("changed since you trusted"), "{err}");
    for h in mgr.hook_specs() {
        let _ = h.run_input("hello").await;
    }
    assert!(!marker.exists(), "the swapped script ran without consent");
}

#[tokio::test]
async fn reviewed_script_still_loads_after_reload() {
    let t = tempfile::tempdir().unwrap();
    let repo = t.path().join("repo");
    let pdir = repo.join(".husk/plugins/guard");
    std::fs::create_dir_all(&pdir).unwrap();
    write_script(&pdir.join("h.sh"), "echo '{\"action\":\"continue\"}'");

    let mut store = agent_plugin::TrustStore::default();
    store.trust_content("guard", &repo, &manifest(&pdir));
    let mut mgr = PluginManager::new(test_paths());
    mgr.trust = store;
    mgr.register_plugin(manifest(&pdir), &repo)
        .await
        .expect("unchanged reviewed content loads");
    assert_eq!(mgr.hook_specs().len(), 1);
}
