//! Workspace-scoped file tools: read, patch, apply, list, search, outline.
//!
//! Every tool here is generic over [`agent_capabilities::WorkspaceCtx`], so this crate
//! names no kernel type: the kernel depends on it, not the other way round.
//! `fs_read` reaches `outline_ts` for the tree-sitter outline when that feature
//! is on, which is why the two ship together.

pub mod apply_patch;
pub mod commit;
pub mod fs_patch;
pub mod fs_read;
pub mod grep;
pub mod list_dir;
#[cfg(feature = "tree-sitter")]
pub mod outline_ts;
