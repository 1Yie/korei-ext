//! Drive a WASM plugin through the real `WasmPlugin` path — the same code
//! the app runs when `kind = "wasm"`. Usage:
//!
//!   cargo run -p agent-plugin --features wasm --example wasm_call -- \
//!       <plugin_dir> <tool_name> '<args-json>'
//!
//! `<plugin_dir>` is the directory containing manifest.json (a relative
//! `entry` resolves inside it). Prints export_tools(), then the call result.

#[cfg(feature = "wasm")]
#[tokio::main]
async fn main() {
    use agent_plugin::wasm::WasmPlugin;
    use agent_plugin::{Plugin, PluginManifest};
    use std::path::PathBuf;

    let mut argv = std::env::args().skip(1);
    let dir = argv.next().expect("usage: wasm_call <dir> <tool> '<json>'");
    let tool = argv.next().expect("usage: wasm_call <dir> <tool> '<json>'");
    let args_json = argv.next().unwrap_or_else(|| "{}".to_string());
    let args: serde_json::Value = serde_json::from_str(&args_json).expect("args not JSON");

    let mpath = PathBuf::from(&dir).join("manifest.json");
    let mut manifest: PluginManifest =
        serde_json::from_str(&std::fs::read_to_string(&mpath).expect("read manifest"))
            .expect("parse manifest");
    manifest.dir = mpath.parent().unwrap().to_path_buf();

    let plugin = WasmPlugin::load(manifest).expect("wasm plugin load");
    println!(
        "── export_tools ──\n{}\n",
        serde_json::to_string_pretty(&plugin.export_tools()).unwrap()
    );
    println!("── call_tool `{tool}` ──");
    match plugin.call_tool(&tool, args).await {
        Ok(out) => println!("{out}"),
        Err(e) => println!("ERROR: {e:#}"),
    }
}

#[cfg(not(feature = "wasm"))]
fn main() {
    eprintln!("rebuild with: cargo run -p agent-plugin --features wasm --example wasm_call -- <dir> <tool> '<json>'");
}
