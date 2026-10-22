//! Shell-specific assessment of a command before the permission gate runs.

use std::sync::Arc;

use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_tool::{Args, CallRisk, Review};

const READONLY_SHELL: &[&str] = &[
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "rg",
    "find",
    "pwd",
    "wc",
    "git status",
    "git diff",
    "git log",
    "git show",
    "git branch",
    "file",
    "stat",
    "du",
    "df",
    "echo",
    "which",
    "env",
    "tree",
    "uname",
    "date",
    "hostname",
    "id",
    "whoami",
];

const DESTRUCTIVE_PHRASES: &[&str] = &["git reset --hard", "git clean -f", "git checkout --"];
const DESTRUCTIVE_BINARIES: &[&str] = &[
    "rm", "mv", "dd", "mkfs", "shutdown", "reboot", "kill", "pkill",
];

pub fn review<C: WorkspaceCtx + SandboxCtx>(args: &Args, ctx: &Arc<C>) -> Review {
    Review {
        risk: args
            .get("command")
            .and_then(|v| v.as_str())
            .map(|command| classify_in(command, &**ctx))
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// [`classify`], plus the two facts only the context knows: whether anything
/// contains the command, and which places it names.
///
/// With the sandbox off nothing stops a write outside the workspace, so a
/// command that reaches outside it and every read-write linked workspace asks
/// first — the same boundary the file tools hold. Two signals, because the
/// audit understands verbs and a shell does not have to use the ones it knows:
/// a *write the extractor recognized* (`rm`, `>`, `cp`), or *any path the line
/// names* at all. The second is what catches `sed -i`, `tee`, `patch`,
/// `git checkout` in another tree, or a program the audit never heard of —
/// the case where "we could not prove the target is in scope" and "it writes
/// elsewhere" are the same answer.
pub fn classify_in<C: WorkspaceCtx + SandboxCtx>(command: &str, ctx: &C) -> CallRisk {
    let risk = classify(command);
    // An explicitly destructive call already asks. A readonly one is a closed
    // set of verbs with no redirects or pipes, so it cannot be smuggling a
    // write. Only "Normal" is a command whose reach has to be checked.
    if risk != CallRisk::Normal || !crate::sandbox_cfg::is_unconfined(ctx) {
        return risk;
    }
    let Ok(root) = ctx.root() else {
        return risk;
    };
    let (_, writable) = crate::sandbox_cfg::linked_mounts(ctx);
    let granted = |p: &std::path::Path| {
        p.starts_with(root)
            || writable.iter().any(|r| p.starts_with(r))
            // `~`-rooted spellings resolve against the home directory before
            // the comparison: `~/x` is not a workspace path.
            || home_rooted(p).is_some_and(|h| h.starts_with(root) || writable.iter().any(|r| h.starts_with(r)))
    };
    let writes = agent_sandbox::writes_out_of_scope(command, root, &writable);
    if !writes.is_empty() {
        return CallRisk::RequiresApproval;
    }
    if agent_sandbox::paths_named(command)
        .iter()
        .any(|p| !granted(p))
    {
        return CallRisk::RequiresApproval;
    }
    risk
}

/// `~/x` / `~` → an absolute path under `$HOME`, when the shell would expand
/// it. Anything else is already absolute or workspace-relative.
fn home_rooted(p: &std::path::Path) -> Option<std::path::PathBuf> {
    let s = p.to_str()?;
    if s != "~" && !s.starts_with("~/") {
        return None;
    }
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(s.trim_start_matches("~/").trim_start_matches('~')))
}

pub fn classify(command: &str) -> CallRisk {
    if is_destructive(command) {
        CallRisk::RequiresApproval
    } else if is_readonly_shell(command) {
        CallRisk::Readonly
    } else {
        CallRisk::Normal
    }
}

fn is_readonly_shell(cmd: &str) -> bool {
    let c = cmd.trim();
    if c.is_empty() {
        return false;
    }
    let starts_readonly = READONLY_SHELL
        .iter()
        .any(|v| c == *v || c.starts_with(&format!("{v} ")));
    if !starts_readonly {
        return false;
    }
    // Reject writes and operators that could smuggle a second command.
    !(c.contains('>')
        || c.contains('|')
        || c.contains("&&")
        || c.contains(';')
        || c.contains("$(")
        || c.contains('`'))
}

fn is_destructive(cmd: &str) -> bool {
    let c = cmd.trim();
    if c.is_empty() {
        return false;
    }
    for phrase in DESTRUCTIVE_PHRASES {
        if c.contains(phrase) {
            return true;
        }
    }
    for segment in c.split([';', '&', '|']) {
        let seg = segment.trim();
        if seg.is_empty() {
            continue;
        }
        let words: Vec<&str> = seg.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let mut idx = 0;
        while idx < words.len() {
            let w = words[idx];
            if w == "sudo" || w == "env" || w == "nohup" || w == "xargs" {
                idx += 1;
                continue;
            }
            if w.starts_with('-') {
                idx += 1;
                continue;
            }
            let bin = std::path::Path::new(w)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(w);
            if DESTRUCTIVE_BINARIES.contains(&bin) {
                return true;
            }
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_command_no_false_positives() {
        for command in [
            "git add .",
            "git add src/main.rs",
            "cargo test --format json",
            "npm run format",
            "echo middle",
            "cat address.txt",
        ] {
            assert!(!is_destructive(command), "{command}");
        }
        for command in [
            "rm file.txt",
            "rm -rf node_modules",
            "/bin/rm -f test",
            "sudo rm -rf /",
            "kill -9 1234",
            "pkill firefox",
            "git reset --hard",
            "git clean -f",
            "echo hi && rm -rf bad",
        ] {
            assert!(is_destructive(command), "{command}");
        }
    }

    #[test]
    fn readonly_commands_cannot_hide_writes_or_chained_commands() {
        for command in ["ls -la", "git status", "cat file.txt", " pwd "] {
            assert_eq!(classify(command), CallRisk::Readonly, "{command}");
        }
        for command in [
            "",
            "cargo test",
            "mkdir demo",
            "cat a > b.txt",
            "ls | sh",
            "echo $(touch a)",
            "echo `touch a`",
            "ls; touch a",
        ] {
            assert_eq!(classify(command), CallRisk::Normal, "{command}");
        }
        assert_eq!(classify("ls && rm -rf x"), CallRisk::RequiresApproval);
    }

    /// Without a sandbox, a write outside every granted root asks; a write
    /// inside the workspace or a read-write linked root does not, and reads
    /// anywhere do not.
    #[test]
    fn unsandboxed_writes_outside_the_granted_roots_ask() {
        use agent_capabilities::{LinkedRoot, LinkedRoots, RootAccess};
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let [ws, rw, other] = ["ws", "rw", "other"].map(|n| base.join(n));
        for d in [&ws, &rw, &other] {
            std::fs::create_dir_all(d).unwrap();
        }
        let roots = Arc::new(LinkedRoots::default());
        roots.set(vec![LinkedRoot {
            path: rw.clone(),
            access: RootAccess::ReadWrite,
        }]);
        let mut ctx =
            crate::TestCtx::with_sandbox(&ws, Arc::new(agent_sandbox::NoneBackend));
        ctx.install_linked_roots(roots);
        let at = |p: &std::path::Path| format!("echo x > {}/a", p.display());
        assert_eq!(classify_in(&at(&ws), &ctx), CallRisk::Normal);
        assert_eq!(classify_in(&at(&rw), &ctx), CallRisk::Normal);
        assert_eq!(classify_in(&at(&other), &ctx), CallRisk::RequiresApproval);
        let read = format!("cat {}/a", other.display());
        assert_eq!(classify_in(&read, &ctx), CallRisk::Readonly);
    }

    /// A real sandbox enforces the boundary itself — no extra question.
    #[test]
    fn a_confining_sandbox_adds_no_question() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::TestCtx::with_sandbox(dir.path(), Arc::new(Confining));
        assert_eq!(classify_in("echo x > /tmp/elsewhere/a", &ctx), CallRisk::Normal);
    }

    struct Confining;

    #[async_trait::async_trait]
    impl agent_sandbox::SandboxBackend for Confining {
        fn id(&self) -> &'static str {
            "bwrap"
        }
        fn tier(&self) -> agent_sandbox::SandboxTier {
            agent_sandbox::SandboxTier::L2
        }
        async fn run_command(
            &self,
            _: &str,
            _: &[&str],
            _: &agent_sandbox::SandboxConfig,
        ) -> anyhow::Result<agent_sandbox::CommandOutput> {
            unreachable!("review never runs the command")
        }
    }
}
