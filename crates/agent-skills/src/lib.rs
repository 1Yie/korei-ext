//! Skills — reusable instruction sets the agent loads on demand.
//!
//! ```text
//! scanner  →  which skills exist (frontmatter only, ~KB)
//! loader   →  one skill's body, read fresh at load time
//! prompt   →  the catalog block and the single instruction frame
//! manager  →  entry point: cached catalog, fresh loads, suggestions
//! ```
//!
//! A skill is knowledge, not capability: loading one injects instructions and
//! nothing else. It cannot widen a tool's `readonly` flag, change a `ToolClass`
//! or skip the permission gate — which is what makes third-party skill text safe
//! to load.

pub mod loader;
pub mod manager;
pub mod prompt;
pub mod scanner;

pub use loader::{LoadError, LoadedSkill};
pub use manager::SkillManager;
pub use scanner::SkillMetadata;
