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

/// Flags that turn a reader into a writer: `find -delete`, `find -exec rm`,
/// `find -fprint`. A file argument to `sort`/`curl`/`cc` is already its own
/// verb, so only the readers' own escaping flags need naming.
const WRITING_FLAGS: &[&str] = &[
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprint0", "-fprintf",
];

pub fn review<C: WorkspaceCtx + SandboxCtx>(args: &Args, ctx: &Arc<C>) -> Review {
    let Some(command) = args.get("command").and_then(|v| v.as_str()) else {
        return Review::default();
    };
    Review {
        risk: classify_in(command, &**ctx),
        // A command the run would refuse anyway must not raise a card first:
        // clicking 允许 on it changes nothing, and the refusal is the answer.
        deny: crate::sandbox_cfg::refuse_unconfined_write(&**ctx, command)
            .err()
            .map(|e| e.to_string()),
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
    // An explicitly destructive call already asks. A read-only line changes
    // nothing wherever it points, so where it reads is not a question.
    if risk != CallRisk::Normal || !crate::sandbox_cfg::is_unconfined(ctx) {
        return risk;
    }
    // Nor is a line that only reads and stages into scrub space: `2>/dev/null`
    // and a `/tmp` scratch file leave nothing to grant.
    if reads_and_scratch(command) {
        return risk;
    }
    let Ok(root) = ctx.root() else {
        return risk;
    };
    let (_, writable) = crate::sandbox_cfg::linked_mounts(ctx);
    // Scrub space (`/tmp`, `/dev/null`) is never a reach worth a card — see
    // `agent_sandbox::is_scratch` for what counts.
    let granted = |p: &std::path::Path| {
        p.starts_with(root)
            || writable.iter().any(|r| p.starts_with(r))
            || agent_sandbox::is_scratch(p)
    };
    if !agent_sandbox::writes_out_of_scope(command, root, &writable).is_empty() {
        return CallRisk::RequiresApproval;
    }
    // Both lists come back resolved against the directory `cd` established, so
    // `../sibling` landing in a linked root reads as in scope instead of as an
    // outside path.
    if agent_sandbox::paths_named(command, Some(root))
        .iter()
        .any(|p| !granted(p))
    {
        return CallRisk::RequiresApproval;
    }
    risk
}

pub fn classify(command: &str) -> CallRisk {
    if is_destructive(command) {
        CallRisk::RequiresApproval
    } else if only_reads(command) {
        CallRisk::Readonly
    } else {
        CallRisk::Normal
    }
}

/// Every segment of the line is a program that cannot write: a read-only verb,
/// a `cd` that only moves the shell, no write redirect, no substitution. A
/// chain of those changes nothing wherever it points, so *where it reads* is
/// not a question the user has to answer — `cd ../other && grep x y` is the
/// ordinary shape of reading a sibling repository.
fn only_reads(cmd: &str) -> bool {
    reads_without_writing(cmd, false)
}

/// The same walk with scrub space excused: a write redirect into `/tmp` or
/// `/dev/null` is how a line stages a scratch file or silences a stream, and
/// it leaves nothing behind the user has to grant.
fn reads_and_scratch(cmd: &str) -> bool {
    reads_without_writing(cmd, true)
}

fn reads_without_writing(cmd: &str, allow_scratch_writes: bool) -> bool {
    use agent_sandbox::shell_ast::{parse, Node};
    fn segment(node: &Node, allow_scratch_writes: bool) -> bool {
        match node {
            Node::And(a, b) | Node::Or(a, b) | Node::Seq(a, b) => {
                segment(a, allow_scratch_writes) && segment(b, allow_scratch_writes)
            }
            Node::Pipe(cmds) => cmds.iter().all(|c| segment(c, allow_scratch_writes)),
            Node::Subshell(inner) => segment(inner, allow_scratch_writes),
            Node::Simple(cmd) => simple_reads(cmd, allow_scratch_writes),
        }
    }
    let c = cmd.trim();
    !c.is_empty() && segment(&parse(c), allow_scratch_writes)
}

fn simple_reads(cmd: &agent_sandbox::shell_ast::Command, allow_scratch_writes: bool) -> bool {
    let writes_anywhere = cmd.redirects.iter().any(|r| {
        r.write
            && !(allow_scratch_writes
                && agent_sandbox::is_scratch(std::path::Path::new(&r.target)))
    });
    if writes_anywhere {
        return false;
    }
    // The parser flags well-formed substitutions; an unterminated backtick or
    // a `$(` split across words still hides a second command, so the raw text
    // is checked too.
    if cmd.has_substitution
        || std::iter::once(&cmd.program)
            .chain(cmd.args.iter())
            .any(|w| w.contains('`') || w.contains("$("))
    {
        return false;
    }
    let prog = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    if prog.is_empty() {
        return false;
    }
    if prog == "cd" {
        return true;
    }
    if !readonly_verb(prog, &cmd.args) {
        return false;
    }
    // `sed -i` rewrites what it was given to read; `grep -i` only ignores
    // case, so the flag is read per program, never on its own.
    let in_place = matches!(prog, "sed" | "perl" | "ruby")
        && cmd.args.iter().any(|a| in_place_flag(a));
    !in_place && !cmd.args.iter().any(|a| WRITING_FLAGS.contains(&a.as_str()))
}

/// `-i` / `-i.bak` / `-pi` / `--in-place[=SUF]` — the flag that makes an
/// editor rewrite the file in place.
fn in_place_flag(arg: &str) -> bool {
    arg == "-i" || arg.starts_with("--in-place") || (arg.starts_with("-i") && !arg.starts_with("--"))
}

/// `git status`-style verbs are two words (`READONLY_SHELL` lists them that
/// way); everything else is matched on the program alone.
fn readonly_verb(prog: &str, args: &[String]) -> bool {
    if let Some(head) = args.first() {
        if READONLY_SHELL.contains(&format!("{prog} {head}").as_str()) {
            return true;
        }
    }
    READONLY_SHELL.contains(&prog)
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
    /// inside the workspace, a read-write linked root or scrub space does not,
    /// and a line that only reads never asks at all.
    ///
    /// The paths are lexical on purpose — the audit compares places, it never
    /// touches the filesystem — and they sit outside `/tmp` so the scrub-space
    /// allowance cannot make the assertions pass by accident.
    #[test]
    fn unsandboxed_writes_outside_the_granted_roots_ask() {
        use agent_capabilities::{LinkedRoot, LinkedRoots, RootAccess};
        let (ws, rw, other) = (
            std::path::PathBuf::from("/zx/ws"),
            std::path::PathBuf::from("/zx/rw"),
            std::path::PathBuf::from("/zx/other"),
        );
        let roots = Arc::new(LinkedRoots::default());
        roots.set(vec![LinkedRoot {
            path: rw.clone(),
            access: RootAccess::ReadWrite,
        }]);
        let mut ctx = crate::TestCtx::with_sandbox(&ws, Arc::new(agent_sandbox::NoneBackend));
        ctx.install_linked_roots(roots);
        let at = |p: &std::path::Path| format!("echo x > {}/a", p.display());
        assert_eq!(classify_in(&at(&ws), &ctx), CallRisk::Normal);
        assert_eq!(classify_in(&at(&rw), &ctx), CallRisk::Normal);
        assert_eq!(classify_in(&at(&other), &ctx), CallRisk::RequiresApproval);
        // Reading anywhere is ordinary shell work, chain or not.
        for read in [
            format!("cat {}/a", other.display()),
            format!("cd {} && grep -rn foo .", other.display()),
            format!("ls {} 2>&1 | head -3", other.display()),
        ] {
            assert_eq!(classify_in(&read, &ctx), CallRisk::Readonly, "{read}");
        }
        // Silencing a stream is not a write of its own: the line reads outside
        // and writes only to `/dev/null`, so nothing here is a reach to grant.
        assert_eq!(
            classify_in(&format!("grep -rn foo {}/src 2>/dev/null | head -20", other.display()), &ctx),
            CallRisk::Normal
        );
        // A write that stays in the workspace or in scrub space asks nothing —
        // the shape of "save a copy before touching the file".
        for write in [
            "cp Cargo.lock /tmp/Cargo.lock.bak".to_string(),
            "cargo build 2>&1 | tee /tmp/build.log".to_string(),
            format!("cp Cargo.lock {}/backup", ws.display()),
        ] {
            assert_eq!(classify_in(&write, &ctx), CallRisk::Normal, "{write}");
        }
        // A write verb pointed at a place no grant reaches still asks.
        assert_eq!(
            classify_in(&format!("cp a.txt {}/b.txt", other.display()), &ctx),
            CallRisk::RequiresApproval
        );
        assert_eq!(
            classify_in(&format!("tar xf a.tgz -C {}", other.display()), &ctx),
            CallRisk::RequiresApproval
        );
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
