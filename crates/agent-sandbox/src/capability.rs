//! Capability IR — the intermediate representation between a shell AST and
//! the policy engine. A capability describes **resource + operation +
//! scope** (`WriteFile{/etc/passwd}`), not the command name (`tee`). The
//! extractor walks a `Node` and yields the capabilities each command needs;
//! unknown programs map to `Execute` + a conservative sandbox rather than a
//! guess.

use crate::shell_ast::{Command, Node};
use std::path::PathBuf;

/// One capability a command requires. Carries the resource it touches.
#[derive(Debug, Clone, PartialEq)]
pub enum Capability {
    /// Read a file (cat, smart_read-equivalent, `<` redirect, `file`…).
    ReadFile { path: PathBuf },
    /// Write/truncate a file (`>`, `tee`, `cp`, editor writes).
    WriteFile { path: PathBuf },
    /// Append (`>>`).
    AppendFile { path: PathBuf },
    /// Delete (`rm`, `rmdir`, `unlink`).
    DeleteFile { path: PathBuf, recursive: bool },
    /// Create a file (`touch`, `> new` when it didn't exist).
    CreateFile { path: PathBuf },
    /// Create a directory (`mkdir`).
    CreateDirectory { path: PathBuf },
    /// Rename/move (`mv`, `git mv`).
    RenameFile { from: PathBuf, to: PathBuf },
    /// Spawn a program — always present; carries the binary name.
    Execute { program: String },
    /// Execute a script piped in (`curl … | sh`, `python -c`, `bash file.sh`).
    ExecuteScript,
    /// Network access (curl/wget/npm/git push/pip…). `target` is the host
    /// when extractable, `None` when the program just reaches out.
    Network { target: Option<String> },
    /// Package install / dependency mutation (npm/cargo/pip/apt install).
    PackageInstall { manager: String },
    /// Privilege escalation (`sudo`, `doas`, `setuid`).
    PrivilegeEscalation,
    /// Needs a managed dev runtime — the command names a toolchain binary
    /// (`npm`, `bun`, `cargo`, `python`, …). Drives the plan's
    /// `EnvironmentPolicy`: the agent asks for "a node runtime", never
    /// for raw env names — the policy derives which bins/vars that means.
    Runtime { toolchain: ToolchainKind },
    /// Device access (`/dev/*`, `dd of=/dev/…`).
    DeviceAccess { path: PathBuf },
    /// Process control (`kill`, `pkill`, `killall`).
    ProcessControl,
    /// Destructive version-control action — `git push --force`,
    /// `git reset --hard`, `git clean -f`, `git checkout --`. Rewrites or
    /// discards history/files; needs its own flag so the card can say
    /// "rewrites git history" instead of a generic network/write note.
    DestructiveVcs { operation: String },
    /// Read a file outside the workspace — scope violation candidate.
    /// (kept separate so policy can deny by scope, not by verb.)
    OutOfScope { path: PathBuf },
}

/// Which managed toolchain a [`Capability::Runtime`] needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolchainKind {
    /// node / npm / npx / yarn / pnpm / tsc / tsx / vite … (nvm, volta, fnm)
    Node,
    /// bun / bunx
    Bun,
    /// deno
    Deno,
    /// python / pip / uv / pytest (pyenv, rye, conda, venv)
    Python,
    /// cargo / rustc / rustup
    Rust,
    /// go / gofmt
    Go,
    /// java / javac / mvn / gradle / sdk (sdkman, system JDK)
    Java,
    /// ruby / gem / bundler
    Ruby,
    /// dotnet / csc
    Dotnet,
}

/// Program name → toolchain it needs. Detected off `Execute` caps — the
/// agent never names env vars; the capability IS the request.
fn runtime_of(prog: &str) -> Option<ToolchainKind> {
    use ToolchainKind as T;
    Some(match prog {
        "node" | "npm" | "npx" | "yarn" | "pnpm" | "tsc" | "tsx" | "vite" | "eslint"
        | "esbuild" | "webpack" | "jest" | "vitest" | "next" | "nuxt" | "turbo" | "corepack"
        | "nodemon" | "pm2" => T::Node,
        "bun" | "bunx" => T::Bun,
        "deno" => T::Deno,
        "python" | "python3" | "pip" | "pip3" | "uv" | "uvx" | "pytest" | "ruff" | "mypy"
        | "ipython" | "poetry" | "conda" | "pipx" => T::Python,
        "cargo" | "rustc" | "rustup" | "rustfmt" | "clippy-driver" => T::Rust,
        "go" | "gofmt" | "golint" | "delve" => T::Go,
        "java" | "javac" | "mvn" | "gradle" | "sdk" | "kotlinc" | "scala" => T::Java,
        "ruby" | "gem" | "bundler" | "rake" | "rails" | "irb" => T::Ruby,
        "dotnet" | "csc" | "msbuild" | "nuget" => T::Dotnet,
        _ => return None,
    })
}

/// Risk level — how dangerous the capability set is, independent of the
/// allow/ask/deny decision. Drives the approval card's color + snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Read-only inspection — auto-run in most modes.
    Low,
    /// Workspace writes / builds / runs — normal agent work.
    Medium,
    /// Network, installs, privilege, out-of-scope writes — confirm.
    High,
    /// Destructive-to-host (`rm -rf /`, fork bomb, `dd of=/dev`) — red card,
    /// forces CoW snapshot + explicit approve.
    Critical,
}

/// Walk a parsed `Node` and collect the capabilities every command needs.
/// Substitutions recurse (their inner commands count too). Pipelines are
/// flattened — a `curl | sh` yields `Network` + `ExecuteScript`.
pub fn extract(node: &Node) -> Vec<Capability> {
    let mut caps = Vec::new();
    walk(node, &mut caps);
    // A pipeline ending in a shell interpreter running piped stdin is a
    // script execution — mark it (the `| sh` / `| bash` / `| python` idiom).
    if let Node::Pipe(cmds) = node {
        if let Some(Node::Simple(last)) = cmds.last() {
            if matches!(
                last.program.as_str(),
                "sh" | "bash"
                    | "zsh"
                    | "python"
                    | "python3"
                    | "node"
                    | "bun"
                    | "deno"
                    | "perl"
                    | "ruby"
            ) && cmds.len() > 1
            {
                caps.push(Capability::ExecuteScript);
            }
        }
    }
    caps
}

fn walk(node: &Node, caps: &mut Vec<Capability>) {
    match node {
        Node::And(a, b) | Node::Or(a, b) | Node::Seq(a, b) => {
            walk(a, caps);
            walk(b, caps);
        }
        Node::Pipe(cmds) => {
            for c in cmds {
                walk(c, caps);
            }
        }
        Node::Subshell(inner) => walk(inner, caps),
        Node::Simple(cmd) => extract_command(cmd, caps),
    }
}

/// Map one `Command` (program + args + redirects) to its capabilities.
/// Readonly verbs contribute `Execute` only — the resource verbs below add
/// the file/network/process capabilities policy actually gates on.
fn extract_command(cmd: &Command, caps: &mut Vec<Capability>) {
    let prog = cmd.program.as_str();
    caps.push(Capability::Execute {
        program: prog.into(),
    });
    if let Some(toolchain) = runtime_of(prog) {
        caps.push(Capability::Runtime { toolchain });
    }

    for r in &cmd.redirects {
        let p = PathBuf::from(&r.target);
        caps.push(if r.write {
            if r.append {
                Capability::AppendFile { path: p }
            } else {
                Capability::WriteFile { path: p }
            }
        } else {
            Capability::ReadFile { path: p }
        });
    }

    let arg_path = |i: usize| {
        cmd.args
            .get(i)
            .map(|a| PathBuf::from(a.trim_matches('"').trim_matches('\'')))
    };

    match prog {
        "rm" | "unlink" | "rmdir" => {
            // Any flag carrying a recursive delete: `-r`, `-rf`, `-R`,
            // `--recursive`. GNU long opts match too.
            let recursive = cmd.args.iter().any(|a| {
                (a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].chars().any(|c| c == 'r' || c == 'R'))
                    || a == "--recursive"
            }) || prog == "rmdir";
            for a in &cmd.args {
                // Skip every flag (incl. `--no-preserve-root`) — only bare
                // operands are paths.
                if !a.starts_with('-') {
                    caps.push(Capability::DeleteFile {
                        path: PathBuf::from(a),
                        recursive,
                    });
                }
            }
        }
        "mv" | "rename" => {
            if let (Some(f), Some(t)) = (arg_path(0), arg_path(1)) {
                caps.push(Capability::RenameFile { from: f, to: t });
            }
        }
        "cp" => {
            if let Some(t) = arg_path(1) {
                caps.push(Capability::WriteFile { path: t });
            }
            if let Some(f) = arg_path(0) {
                caps.push(Capability::ReadFile { path: f });
            }
        }
        "mkdir" => {
            for a in &cmd.args {
                if !a.starts_with('-') {
                    caps.push(Capability::CreateDirectory {
                        path: PathBuf::from(a),
                    });
                }
            }
        }
        "touch" => {
            for a in &cmd.args {
                if !a.starts_with('-') {
                    caps.push(Capability::CreateFile {
                        path: PathBuf::from(a),
                    });
                }
            }
        }
        "tee" => {
            for a in &cmd.args {
                if !a.starts_with('-') {
                    caps.push(Capability::WriteFile {
                        path: PathBuf::from(a),
                    });
                }
            }
        }
        "cat" | "head" | "tail" | "less" | "more" | "file" | "stat" | "wc" => {
            for a in &cmd.args {
                if !a.starts_with('-') {
                    caps.push(Capability::ReadFile {
                        path: PathBuf::from(a),
                    });
                }
            }
        }
        "grep" | "rg" | "find" => {
            // the *path* arg (last non-flag, non-pattern) — heuristic: any arg
            // that looks like a path is a read target.
            for a in &cmd.args {
                if a.contains('/') && !a.starts_with('-') {
                    caps.push(Capability::ReadFile {
                        path: PathBuf::from(a),
                    });
                }
            }
        }
        "sudo" | "doas" => {
            caps.push(Capability::PrivilegeEscalation);
            // the wrapped command counts as an execute too — extract it.
            if let Some(first) = cmd.args.first() {
                if !first.starts_with('-') {
                    caps.push(Capability::Execute {
                        program: first.clone(),
                    });
                }
            }
        }
        "curl" | "wget" => {
            let target = cmd
                .args
                .iter()
                .find(|a| a.contains("://") || a.contains('.'))
                .and_then(|a| a.split("://").nth(1))
                .and_then(|h| h.split('/').next())
                .map(|s| s.to_string());
            caps.push(Capability::Network { target });
        }
        "ssh" | "scp" | "rsync" | "nc" | "ncat" | "telnet" => {
            caps.push(Capability::Network { target: None });
        }
        "npm" | "yarn" | "pnpm" | "bun" | "pip" | "pip3" | "cargo" | "apt" | "apt-get" | "brew"
        | "dnf" | "pacman" | "gem" | "composer" => {
            let sub = cmd.args.first().map(|s| s.as_str()).unwrap_or("");
            // `npm run dev` / `npm start` / `pnpm dev` — dev servers bind a
            // listening socket; unshare-net would strand them on a private
            // loopback, so they get the shared-network policy.
            let is_dev_serve = cmd
                .args
                .iter()
                .any(|a| matches!(a.as_str(), "dev" | "start" | "serve"));
            if is_dev_serve && matches!(prog, "npm" | "yarn" | "pnpm" | "bun") {
                caps.push(Capability::Network { target: None });
            }
            if matches!(
                sub,
                "install" | "add" | "i" | "remove" | "uninstall" | "update" | "upgrade"
            ) {
                caps.push(Capability::PackageInstall {
                    manager: prog.into(),
                });
                caps.push(Capability::Network { target: None });
                // Which dirs the manager actually writes — npm→node_modules,
                // cargo→target/+Cargo.toml, pip→site-packages, apt→system.
                let written = match prog {
                    "npm" | "yarn" | "pnpm" | "bun" => {
                        vec![PathBuf::from("node_modules"), PathBuf::from("package.json")]
                    }
                    "cargo" => vec![
                        PathBuf::from("target"),
                        PathBuf::from("Cargo.toml"),
                        PathBuf::from("Cargo.lock"),
                    ],
                    "pip" | "pip3" => vec![PathBuf::from("site-packages")],
                    "apt" | "apt-get" | "dnf" | "pacman" | "brew" => {
                        vec![PathBuf::from("/usr"), PathBuf::from("/var")]
                    }
                    "gem" => vec![PathBuf::from("gems")],
                    "composer" => vec![PathBuf::from("vendor")],
                    _ => vec![],
                };
                for p in written {
                    caps.push(Capability::WriteFile { path: p });
                }
            } else if prog == "bun" {
                let has_script = cmd.args.iter().any(|a| {
                    a == "-e"
                        || a == "-c"
                        || a == "run"
                        || a.ends_with(".js")
                        || a.ends_with(".ts")
                        || a.ends_with(".mjs")
                        || a.ends_with(".cjs")
                });
                if has_script {
                    caps.push(Capability::ExecuteScript);
                }
            }
        }
        // Listeners — binaries whose normal mode IS binding a socket. A
        // private netns would strand them on an unreachable loopback, so
        // the plan gives them shared network (egress stays unrestricted
        // for them, but `persistent` services need inbound anyway).
        "nginx" | "httpd" | "apache2" | "caddy" | "lighttpd" | "mysqld" | "mariadbd"
        | "postgres" | "postmaster" | "redis-server" | "memcached" | "mongod" | "influxd"
        | "sshd" | "rabbitmq-server" | "prometheus" | "minio" | "uvicorn" | "gunicorn"
        | "hypercorn" | "daphne" | "vite" | "http-server" | "serve" | "openresty" => {
            caps.push(Capability::Network { target: None });
        }
        // `php -S 127.0.0.1:8080` — built-in dev server.
        "php" if cmd.args.iter().any(|a| a == "-S") => {
            caps.push(Capability::Network { target: None });
        }
        // `python -m http.server` / `python3 -m http.server`.
        "python" | "python3" | "python2"
            if cmd.args.windows(2).any(|w| {
                w[0] == "-m" && matches!(w[1].as_str(), "http.server" | "SimpleHTTPServer")
            }) =>
        {
            caps.push(Capability::Network { target: None });
        }
        // Subcommand servers — `flask run`, `rails s`, `hugo server`,
        // `next dev`, `ng serve`, `streamlit run`, `jupyter lab`, …
        "flask" | "rails" | "hugo" | "jekyll" | "next" | "nuxt" | "astro" | "ng" | "expo"
        | "streamlit" | "jupyter" | "wp" | "hexo" | "zola"
            if cmd.args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "run"
                        | "s"
                        | "server"
                        | "serve"
                        | "dev"
                        | "start"
                        | "lab"
                        | "notebook"
                        | "develop"
                )
            }) =>
        {
            caps.push(Capability::Network { target: None });
        }
        "git" => {
            let sub = cmd.args.first().map(|s| s.as_str()).unwrap_or("");
            match sub {
                "push"
                    if cmd
                        .args
                        .iter()
                        .any(|a| a == "--force" || a == "-f" || a == "--force-with-lease") =>
                {
                    caps.push(Capability::DestructiveVcs {
                        operation: "git push --force".into(),
                    });
                    caps.push(Capability::Network { target: None });
                }
                "reset" if cmd.args.iter().any(|a| a == "--hard") => {
                    caps.push(Capability::DestructiveVcs {
                        operation: "git reset --hard".into(),
                    });
                }
                "clean"
                    if cmd
                        .args
                        .iter()
                        .any(|a| a.contains('f') && a.starts_with('-')) =>
                {
                    caps.push(Capability::DestructiveVcs {
                        operation: "git clean -f".into(),
                    });
                }
                "checkout" | "restore"
                    if cmd
                        .args
                        .iter()
                        .any(|a| a == "--" || a.starts_with('-') && a.contains('f')) =>
                {
                    caps.push(Capability::DestructiveVcs {
                        operation: format!("git {sub} — discards changes"),
                    });
                }
                "push" | "pull" | "fetch" | "clone" | "submodule" | "remote" => {
                    caps.push(Capability::Network { target: None });
                }
                _ => {}
            }
        }
        "dd" => {
            for a in &cmd.args {
                if let Some(rest) = a.strip_prefix("of=") {
                    if rest.starts_with("/dev") {
                        caps.push(Capability::DeviceAccess {
                            path: PathBuf::from(rest),
                        });
                    } else {
                        caps.push(Capability::WriteFile {
                            path: PathBuf::from(rest),
                        });
                    }
                }
            }
        }
        "kill" | "pkill" | "killall" => {
            caps.push(Capability::ProcessControl);
        }
        // interpreters running a script file / -c / -s / - — ExecuteScript.
        // `bash -s`, `python -` read a script from stdin; `-c "cmd"` is a
        // literal script. Also catch `eval "$(curl …)"` style builtins.
        "sh" | "bash" | "zsh" | "python" | "python3" | "node" | "deno" | "perl" | "ruby"
        | "eval" => {
            let has_script = cmd.args.iter().any(|a| {
                a == "-c" || a == "-s" || a == "-" || a == "-e" // stdin / inline script
                    || a.ends_with(".sh") || a.ends_with(".py")
                    || a.ends_with(".js") || a.ends_with(".ts")
                    || a.ends_with(".mjs") || a.ends_with(".cjs")
                    || a.ends_with(".pl") || a.ends_with(".rb")
                    || prog == "eval" // `eval` always executes its arg
            });
            if has_script {
                caps.push(Capability::ExecuteScript);
            }
        }
        _ => {}
    }

    // Recurse into `$( )` / backtick substitutions — they run commands too.
    for sub in &cmd.substitutions {
        walk(sub, caps);
    }
}

/// Compute the aggregate risk level for a capability set — the max of the
/// per-capability risk. Independent of the policy decision.
pub fn risk_of(caps: &[Capability]) -> RiskLevel {
    let mut risk = RiskLevel::Low;
    for c in caps {
        let r = match c {
            Capability::PrivilegeEscalation
            | Capability::DeviceAccess { .. }
            | Capability::DestructiveVcs { .. }
            | Capability::OutOfScope { .. } => RiskLevel::High,
            Capability::ExecuteScript
            | Capability::PackageInstall { .. }
            | Capability::Network { .. }
            | Capability::ProcessControl => RiskLevel::High,
            Capability::DeleteFile { path, .. } => {
                // Deleting `/` or `~` is critical; workspace deletes are medium.
                let s = path.to_string_lossy();
                if s == "/"
                    || s == "/*"
                    || s == "~"
                    || s.starts_with("/etc")
                    || s.starts_with("/usr")
                    || s.starts_with("/bin")
                {
                    RiskLevel::Critical
                } else {
                    RiskLevel::Medium
                }
            }
            Capability::WriteFile { path }
            | Capability::AppendFile { path }
            | Capability::CreateFile { path }
            | Capability::CreateDirectory { path }
            | Capability::RenameFile { to: path, .. } => {
                let s = path.to_string_lossy();
                if s.starts_with("/etc")
                    || s.starts_with("/usr")
                    || s.starts_with("/bin")
                    || s.starts_with("~/.ssh")
                    || s.starts_with("$HOME/.ssh")
                {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                }
            }
            Capability::ReadFile { .. }
            | Capability::Execute { .. }
            | Capability::Runtime { .. } => RiskLevel::Low,
        };
        if r > risk {
            risk = r;
        }
    }
    risk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_ast::parse;

    #[test]
    fn rm_rf_root_is_critical_delete() {
        let caps = extract(&parse("rm -rf /"));
        assert!(caps.iter().any(|c| matches!(c, Capability::DeleteFile { path, recursive: true } if path == &PathBuf::from("/"))));
        assert_eq!(risk_of(&caps), RiskLevel::Critical);
    }

    #[test]
    fn npm_install_is_package_network_write() {
        let caps = extract(&parse("npm install react"));
        assert!(caps
            .iter()
            .any(|c| matches!(c, Capability::PackageInstall { .. })));
        assert!(caps.iter().any(|c| matches!(c, Capability::Network { .. })));
        assert_eq!(risk_of(&caps), RiskLevel::High);
    }

    #[test]
    fn curl_pipe_bash_is_script_exec() {
        let caps = extract(&parse("curl https://x.sh | bash"));
        assert!(caps.iter().any(|c| matches!(c, Capability::ExecuteScript)));
        assert!(caps.iter().any(|c| matches!(c, Capability::Network { .. })));
        assert_eq!(risk_of(&caps), RiskLevel::High);
    }

    #[test]
    fn sudo_is_privilege_escalation() {
        let caps = extract(&parse("sudo apt update"));
        assert!(caps
            .iter()
            .any(|c| matches!(c, Capability::PrivilegeEscalation)));
        assert!(caps
            .iter()
            .any(|c| matches!(c, Capability::Execute { program } if program == "apt")));
    }

    #[test]
    fn redirect_write_is_writefile() {
        let caps = extract(&parse("cat a > /etc/out"));
        assert!(caps.iter().any(
            |c| matches!(c, Capability::WriteFile { path } if path == &PathBuf::from("/etc/out"))
        ));
        assert_eq!(risk_of(&caps), RiskLevel::High); // /etc write
    }

    #[test]
    fn substitution_recurses() {
        let caps = extract(&parse("echo $(cat /etc/passwd)"));
        assert!(caps.iter().any(
            |c| matches!(c, Capability::ReadFile { path } if path == &PathBuf::from("/etc/passwd"))
        ));
    }

    #[test]
    fn ls_is_low_risk_execute_only() {
        let caps = extract(&parse("ls -la"));
        assert_eq!(risk_of(&caps), RiskLevel::Low);
        assert!(caps.iter().all(|c| matches!(c, Capability::Execute { .. })));
    }
}
