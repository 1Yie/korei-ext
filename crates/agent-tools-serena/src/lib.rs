//! `serena` — Serena's semantic code tools behind one meta-tool.
//!
//! `serena start-mcp-server` runs as an MCP child over stdio (newline-delimited
//! JSON-RPC), so this crate needs no HTTP client and no plugin bridge — it
//! spawns the child directly.
//!
//! The meta-tool is generic over the tool context, so this crate names no
//! kernel type: the kernel depends on it, not the other way round. Unprepared
//! calls share one server per workspace root. Prepared calls require
//! [`manager::install_registry`] and keep one server per private project and
//! authorization.
//!
//! ```text
//! unprepared workspace → SerenaManager (one slot per root)
//! prepared session     → SerenaRegistry (one slot per private project and authorization)
//!                          └── SerenaBridge       — child process + JSON-RPC plumbing
//!                          └── SerenaToolCatalog  — cached `tools/list`
//! ```
//!
//! A missing `uvx`/serena or a failed start fails only that call and carries the
//! child's stderr tail; a dead child is replaced on the next call. Bootstrap
//! (`uvx --from git+…`) needs network — `network: false` describes execution.
//! `serena_status` inspects without starting a server; `serena_stop` waits for
//! process and stdio cleanup.

pub mod bridge;
pub mod catalog;
pub mod manager;
pub mod tool;

pub use bridge::{BridgeFactory, McpBridge, SerenaBridge, SerenaLaunch, SerenaToolInfo};
pub use catalog::SerenaToolCatalog;
pub use manager::{
    install_registry, manager_for, registry, shutdown, SerenaManager, SerenaRegistry,
    SerenaRegistrySlot, SerenaStatus,
};

use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_tool::ToolSpec;

pub fn spec<C>() -> ToolSpec<C>
where
    C: WorkspaceCtx + SandboxCtx,
{
    tool::spec::<C>()
}
