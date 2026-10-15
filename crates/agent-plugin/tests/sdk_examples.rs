//! The shipped hook examples under `examples/` — each manifest is parsed the
//! way discovery parses it, its hook driven end-to-end through the real wire
//! contract (spawn + stdin payload + stdout verdict). An example that rots
//! fails here instead of in a user's plugin dir.

use std::path::{Path, PathBuf};

fn example_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

/// Whether `bin` is findable on the ambient PATH. The hook child runs
/// env-clear, so a bare name only resolves when the default path has it —
/// or the manifest passed the host PATH through (the TS example does).
fn spawnable(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

fn hook_for(dir: &Path) -> Vec<agent_plugin::CommandHook> {
    let text = std::fs::read_to_string(dir.join("manifest.json"))
        .unwrap_or_else(|e| panic!("{}: manifest unreadable: {e}", dir.display()));
    let mut m: agent_plugin::PluginManifest = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: manifest unparsable: {e}", dir.display()));
    // Discovery fills `dir` — hook commands resolve relative to it.
    m.dir = dir.to_path_buf();
    m.validate()
        .unwrap_or_else(|e| panic!("{}: manifest invalid: {e}", dir.display()));
    agent_plugin::hooks_from_manifest(&m, &[])
}

/// Every example appends 喵～ to the answer it is handed.
#[tokio::test]
async fn examples_rewrite_the_final_answer() {
    for (name, needs) in [
        ("meow-sh", "sh"),
        ("meow-py", "python3"),
        ("meow-ts", "bun"),
    ] {
        if !spawnable(needs) {
            eprintln!("skip {name}: `{needs}` not on PATH");
            continue;
        }
        let dir = example_dir(name);
        let hooks = hook_for(&dir);
        assert_eq!(hooks.len(), 1, "{name}: expected exactly one hook");
        let out = hooks[0].run_response("plain answer").await;
        assert_eq!(
            out.as_deref(),
            Some("plain answer 喵～"),
            "{name}: hook did not rewrite the answer"
        );
    }
}
