//! Networking tools: fetch a URL, and search for or download media assets.
//!
//! Generic over [`agent_capabilities::WorkspaceCtx`] like the other tool packages, so
//! this crate names no kernel type. `net` is the shared HTTP layer — SSRF
//! guards, redirect policy, bounded bodies — that `web_fetch` and `assets`
//! both go through rather than talking to `reqwest` directly.

pub mod assets;
pub(crate) mod net;
pub mod web_fetch;
