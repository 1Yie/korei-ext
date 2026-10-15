//! `serena` — Serena's semantic code tools behind one meta-tool.
//!
//! `serena start-mcp-server` runs as an MCP child over stdio (newline-delimited
//! JSON-RPC), so this crate needs no HTTP client and no plugin bridge — it
//! spawns the child directly.
//!
//! The meta-tool is generic over [`agent_capabilities::WorkspaceCtx`] (it reads only the
//! workspace root), so this crate names no kernel type: the kernel depends on it,
//! not the other way round.
//!
//! ```text
//! workspace  →  SerenaManager (one slot per root)
//!                 └── SerenaBridge       — child process + JSON-RPC plumbing
//!                 └── SerenaToolCatalog  — cached `tools/list`
//! ```
//!
//! A missing `uvx`/serena or a failed start fails only that call and carries the
//! child's stderr tail; a dead child is replaced on the next call. Bootstrap
//! (`uvx --from git+…`) needs network — `network: false` describes execution.

pub mod bridge;
pub mod catalog;
pub mod manager;
pub mod tool;

pub use bridge::{BridgeFactory, McpBridge, SerenaBridge, SerenaLaunch, SerenaToolInfo};
pub use catalog::SerenaToolCatalog;
pub use manager::{manager_for, shutdown, SerenaManager};

use agent_capabilities::WorkspaceCtx;
use agent_tool::ToolSpec;

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    tool::spec::<C>()
}
