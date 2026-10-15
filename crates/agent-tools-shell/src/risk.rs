//! Shell-specific assessment of a command before the permission gate runs.

use std::sync::Arc;

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

pub fn review<C>(args: &Args, _: &Arc<C>) -> Review {
    Review {
        risk: args
            .get("command")
            .and_then(|v| v.as_str())
            .map(classify)
            .unwrap_or_default(),
        ..Default::default()
    }
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
}
