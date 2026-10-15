//! Env sanitization — applied to every spawn, sandboxed or not.
//!
//! The allowlist is the security boundary; the denylist (matched on uppercased
//! name and value) is defense-in-depth. `extra` vars are caller-built
//! infrastructure (TMPDIR, cache redirects): they skip the allowlist, never the
//! denylist.
//!
//! PATH is treated as a capability: `rebuild_path` appends discovered dev bins
//! (GUI launches inherit a minimal PATH) and each backend then prunes entries its
//! mounts cannot resolve — they resolve nothing inside and only widen the hijack
//! surface. `HOME` stays the real home: mounted toolchains live at real paths, and
//! sensitive subdirs are masked by the backend instead.

/// Names kept from the host env (exact match, case-insensitive).
const ALLOWLIST: &[&str] = &[
    "PATH",
    "LANG",
    "TERM",
    "HOME",
    "TMPDIR",
    "USER",
    "SHELL",
    "COLORTERM",
    "EDITOR",
    "VISUAL",
    "TZ",
    // Display session — a GUI-launched Tauri app spawns the agent, and its
    // `bash`/`test_runner` tools must be able to launch GUI binaries (`code`,
    // `firefox`) or drive `xdotool`/`scrot` for computer-use. Stripping these
    // in `none` (loud-unsandboxed) mode breaks the desktop; `bwrap` clears the
    // env itself anyway, so this only reaches the host-spawn path.
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_SESSION_TYPE",
    "XDG_RUNTIME_DIR",
    "XDG_CURRENT_DESKTOP",
    "DBUS_SESSION_BUS_ADDRESS",
    // toolchain vars the workspace needs
    "CARGO_HOME",
    "GOPATH",
    "GOCACHE",
    "NVM_DIR",
    "NODE_ENV",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "RUSTUP_HOME",
    "JAVA_HOME",
    // Node / JS / Bun / Deno runtimes
    "VOLTA_HOME",
    "BUN_INSTALL",
    "FNM_DIR",
    "PNPM_HOME",
    "DENO_INSTALL",
    // Python / Version managers
    "PYENV_ROOT",
    "ASDF_DIR",
    "ASDF_DATA_DIR",
    "MISE_DATA_DIR",
    // JVM / Mobile / Toolchain SDKs
    "SDKMAN_DIR",
    "GRADLE_USER_HOME",
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "FLUTTER_ROOT",
    "GOROOT",
    "CARGO_TARGET_DIR",
];

/// Prefixes kept (e.g. `LC_*` locale vars).
const ALLOW_PREFIXES: &[&str] = &["LC_"];

/// Name/value patterns that always strip — matched against the
/// **uppercased** name and value, so `database_url` and `AWS_*` die the same
/// as their uppercase forms (Windows env is case-insensitive).
const DENY_PATTERNS: &[&str] = &[
    "_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_URL",
    "_URI",
    "_DSN",
    "PRIVATE",
    "AWS_",
    "GITHUB_",
    "OPENAI_",
    "ANTHROPIC_",
    "DATABASE_URL",
    "MONGODB_URI",
    "REDIS_AUTH",
    "SENTRY_DSN",
    "COOKIE",
];

/// Dev-runtime bin dirs that a GUI-launched app's PATH misses — the
/// display manager hands the app a minimal PATH (`/usr/bin:/bin`), and
/// the shell profile lines that add `~/.bun/bin`, `~/.volta/bin`,
/// `~/.cargo/bin` never ran. Directories that exist are appended to
/// PATH post-sanitization so dev toolchains resolve inside the sandbox
/// exactly as they would from a terminal.
const HOME_BIN_DIRS: &[&str] = &[
    ".bun/bin",
    ".volta/bin",
    ".deno/bin",
    ".cargo/bin",
    ".local/bin",
    "go/bin",
    ".pnpm",
    ".yarn/bin",
    ".pyenv/bin",
    ".pyenv/shims",
    ".rye/shims",
    ".asdf/bin",
    ".asdf/shims",
    ".mise/shims",
    ".local/share/mise/shims",
    ".fnm",
    ".local/share/fnm",
    ".local/pipx/bin",
    "miniconda3/bin",
    "anaconda3/bin",
];

/// Glob-ish patterns under HOME — one `*` matches exactly one path
/// segment. `true` = take only the newest match (versioned runtimes like
/// nvm — an older `node` shadowing the current one is worse than none);
/// `false` = take all (per-tool dirs like sdkman candidates).
const HOME_BIN_GLOBS: &[(&str, bool)] = &[
    (".nvm/versions/node/*/bin", true),
    (".sdkman/candidates/*/current/bin", false),
];

/// Toolchain vars injected when their directory exists but the var is
/// absent — a GUI launch never sourced the profile that exports them.
/// (var, dir under HOME)
const TOOLCHAIN_VAR_DEFAULTS: &[(&str, &str)] = &[
    ("VOLTA_HOME", ".volta"),
    ("BUN_INSTALL", ".bun"),
    ("CARGO_HOME", ".cargo"),
    ("RUSTUP_HOME", ".rustup"),
    ("NVM_DIR", ".nvm"),
    ("DENO_INSTALL", ".deno"),
    ("PNPM_HOME", ".local/share/pnpm"),
    ("GOPATH", "go"),
    ("PYENV_ROOT", ".pyenv"),
    ("SDKMAN_DIR", ".sdkman"),
    ("MISE_DATA_DIR", ".local/share/mise"),
    ("ASDF_DATA_DIR", ".asdf"),
    ("FLUTTER_ROOT", "Development/flutter"),
];

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Existing bin dirs discovered under HOME — see [`HOME_BIN_DIRS`] and
/// [`HOME_BIN_GLOBS`].
fn dev_bin_dirs() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Some(home) = dirs_home() else { return out };
    for rel in HOME_BIN_DIRS {
        let p = home.join(rel);
        if p.is_dir() {
            out.push(p);
        }
    }
    for (pattern, newest_only) in HOME_BIN_GLOBS {
        let Some(star) = pattern.find('*') else {
            continue;
        };
        let parent = home.join(&pattern[..star]);
        let suffix = pattern[star + 1..].trim_start_matches('/');
        let Ok(rd) = std::fs::read_dir(&parent) else {
            continue;
        };
        let mut cands: Vec<std::path::PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path().join(suffix))
            .filter(|p| p.is_dir())
            .collect();
        if *newest_only {
            // nvm: honor the configured default first — the active version
            // is whatever `alias/default` (or a short alias chain) points
            // at, not whatever happens to have the newest mtime.
            if pattern.starts_with(".nvm") {
                if let Some(dir) = nvm_default_bin(&home) {
                    if cands.contains(&dir) {
                        out.push(dir);
                        continue;
                    }
                }
            }
            // Versioned manager dirs — newest install (mtime) wins;
            // lexicographic order lies (`v9` > `v20` as strings).
            cands.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
            if let Some(p) = cands.pop() {
                out.push(p);
            }
        } else {
            out.extend(cands);
        }
    }
    out
}

/// Resolve nvm's configured default to a `versions/node/<ver>/bin` dir —
/// follows `.nvm/alias/default` plus one level of chained aliases
/// (`default` → `lts/*` → `lts/iron` → `v20.x`). Returns `None` when the
/// alias can't be resolved to an installed version.
fn nvm_default_bin(home: &std::path::Path) -> Option<std::path::PathBuf> {
    let alias_root = home.join(".nvm/alias");
    let mut name = std::fs::read_to_string(alias_root.join("default"))
        .ok()?
        .trim()
        .to_string();
    // Alias chains: `default` may contain `lts/*` which itself is an
    // alias file — resolve up to 3 hops until it looks like a version.
    for _ in 0..3 {
        let normalized = name.trim().trim_start_matches('v');
        let candidate = home.join(format!(".nvm/versions/node/v{normalized}/bin"));
        if candidate.is_dir() {
            return Some(candidate);
        }
        name = std::fs::read_to_string(alias_root.join(name.trim()))
            .ok()?
            .trim()
            .to_string();
    }
    None
}

/// Filter the host env to a sanitized map.
///
/// Security model: the **allowlist is the boundary**; the denylist is
/// heuristic defense-in-depth on name *and* value (a secret named `FOO`
/// still dies by not being allowlisted, not by pattern luck).
pub fn sanitize_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in std::env::vars() {
        if is_denied(&name, &value) {
            continue;
        }
        if is_allowed(&name) {
            out.push((name, value));
        }
    }
    // Caller-supplied vars skip the *allowlist* (they're infrastructure —
    // TMPDIR, cache redirects) but still pass the denylist, so the
    // trusted channel can't be used to inject a secret-shaped variable.
    for (name, value) in extra {
        if !is_denied(name, value) {
            out.push((name.clone(), value.clone()));
        }
    }
    out
}

/// Apply the plan's [`crate::plan::EnvironmentPolicy`] to a sanitized env — the one
/// point where PATH becomes a capability.
///
/// `DevToolchain` (the default) appends discovered dev bin dirs and injects
/// toolchain vars; `Minimal`/`Select` keep the baseline PATH only (`Select`'s
/// per-toolchain gating degrades to `Minimal` until a caller trusts detection).
/// Either way PATH is then pruned to `allowed_roots` minus `denied_roots`.
pub fn apply_environment_policy(
    envs: &mut Vec<(String, String)>,
    policy: &crate::plan::EnvironmentPolicy,
    allowed_roots: Option<&[std::path::PathBuf]>,
    denied_roots: &[std::path::PathBuf],
) {
    if matches!(policy, crate::plan::EnvironmentPolicy::DevToolchain) {
        rebuild_path(envs);
        inject_toolchain_vars(envs);
    }
    for (k, v) in envs.iter_mut() {
        if k.eq_ignore_ascii_case("PATH") {
            *v = prune_path(v, allowed_roots, denied_roots);
        }
    }
}

/// Allowlist check — name is a known-safe variable (exact match or `LC_`
/// prefix), case-insensitive.
pub fn is_allowed(name: &str) -> bool {
    let uname = name.to_uppercase();
    ALLOWLIST.iter().any(|a| uname == *a) || ALLOW_PREFIXES.iter().any(|p| uname.starts_with(p))
}

/// Full policy check for external pre-flight (`bash` tool and friends) —
/// a variable is safe to pass only when allowlisted **and** not
/// denylisted. Callers use this instead of composing checks themselves
/// so the policy can't drift between call sites.
pub fn is_safe_env(name: &str, value: &str) -> bool {
    is_allowed(name) && !is_denied(name, value)
}

/// Prune a PATH string to entries a sandbox can resolve.
///
/// `allowed_roots: Some` keeps an entry only under one of those roots (the dirs bound
/// into the namespace — an entry at an unmounted dir resolves nothing and only widens
/// the hijack surface); `None` keeps every absolute entry (raw-host mode).
/// `denied_roots` always wins: entries under the workspace or the scratch dirs are
/// agent-writable, so inheriting one is a planted-binary channel. Non-absolute entries
/// are dropped outright — they resolve against the sandbox's cwd.
pub fn prune_path(
    path_value: &str,
    allowed_roots: Option<&[std::path::PathBuf]>,
    denied_roots: &[std::path::PathBuf],
) -> String {
    let kept: Vec<std::path::PathBuf> = std::env::split_paths(std::ffi::OsStr::new(path_value))
        .filter(|p| {
            if !p.is_absolute() {
                return false;
            }
            if denied_roots.iter().any(|d| p.starts_with(d)) {
                return false;
            }
            match allowed_roots {
                None => true,
                Some(roots) => roots.iter().any(|a| p.starts_with(a)),
            }
        })
        .collect();
    std::env::join_paths(&kept)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Rebuild PATH = inherited entries + discovered dev bin dirs (deduped,
/// appended). A GUI-launched app inherits the display manager's PATH, so
/// without this `bun`/`node`/`cargo` are `command not found` inside the
/// sandbox even though their directories are mounted.
fn rebuild_path(out: &mut Vec<(String, String)>) {
    use std::collections::BTreeSet;
    let inherited = out
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let mut parts: Vec<std::path::PathBuf> =
        std::env::split_paths(std::ffi::OsStr::new(&inherited)).collect();
    if parts.is_empty() {
        parts = ["/usr/local/bin", "/usr/bin", "/bin"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
    }
    for dir in dev_bin_dirs() {
        parts.push(dir);
    }
    // Dedup the whole list, keeping first occurrence, so inherited duplicates
    // and discovered dirs that were already present both collapse.
    let mut seen = BTreeSet::new();
    parts.retain(|p| seen.insert(p.clone()));
    let merged = std::env::join_paths(parts)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| inherited.clone());
    match out.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case("PATH")) {
        Some(entry) => entry.1 = merged,
        None => out.push(("PATH".into(), merged)),
    }
}

/// Inject toolchain vars a GUI launch never exported — only when the
/// directory actually exists and nothing (host or `extra`) already set
/// the var.
fn inject_toolchain_vars(out: &mut Vec<(String, String)>) {
    let Some(home) = dirs_home() else { return };
    for (var, rel) in TOOLCHAIN_VAR_DEFAULTS {
        if out.iter().any(|(n, _)| n.eq_ignore_ascii_case(var)) {
            continue;
        }
        let dir = home.join(rel);
        if dir.exists() {
            out.push(((*var).to_string(), dir.to_string_lossy().into_owned()));
        }
    }
}

/// Is a name denied by the denylist? Exposed for `bash` tool pre-flight.
pub fn is_denied(name: &str, value: &str) -> bool {
    let uname = name.to_uppercase();
    let uvalue = value.to_uppercase();
    DENY_PATTERNS
        .iter()
        .any(|p| uname.contains(p) || uvalue.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_secrets_case_insensitive() {
        let out = sanitize_env(&[]);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        // Common secrets must never survive.
        for forbidden in ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL"] {
            assert!(!names.contains(&forbidden), "{forbidden} leaked");
        }
    }

    #[test]
    fn lowercase_database_url_stripped() {
        // is_denied matches on uppercased name+value.
        assert!(is_denied("database_url", "postgres://u:p@h/db"));
        assert!(is_denied("my_secret", "x"));
        assert!(is_denied("anything", "contains_AWS_thing"));
        assert!(!is_denied("PATH", "/usr/bin"));
        assert!(!is_denied("CARGO_HOME", "/home/u/.cargo"));
    }

    #[test]
    fn keeps_toolchain_and_locale() {
        std::env::set_var("TEST_AGENT_CARGO_HOME_X", "v");
        let out = sanitize_env(&[("FORCED".into(), "1".into())]);
        assert!(out.iter().any(|(n, _)| n == "FORCED"));
    }

    #[test]
    fn keeps_bun_and_volta_toolchain_vars() {
        std::env::set_var("VOLTA_HOME", "/home/user/.volta");
        std::env::set_var("BUN_INSTALL", "/home/user/.bun");
        let out = sanitize_env(&[]);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"VOLTA_HOME"));
        assert!(names.contains(&"BUN_INSTALL"));
    }

    #[test]
    fn extra_cannot_bypass_denylist() {
        // The trusted channel is for infrastructure vars — a caller
        // injecting a secret-shaped var must be filtered exactly like a
        // host var. Regression test for the P0 bypass.
        let out = sanitize_env(&[
            ("OPENAI_API_KEY".into(), "sk-test".into()),
            ("DATABASE_URL".into(), "postgres://u:p@h/db".into()),
            ("MY_TOKEN".into(), "tok".into()),
            ("npm_config_cache".into(), "/tmp/npm".into()), // legit infra — survives
            ("INNOCENT_EXTRA".into(), "v".into()),          // unallowlisted — survives (trusted)
        ]);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        for forbidden in ["OPENAI_API_KEY", "DATABASE_URL", "MY_TOKEN"] {
            assert!(!names.contains(&forbidden), "{forbidden} leaked via extra");
        }
        assert!(names.contains(&"npm_config_cache"));
        assert!(names.contains(&"INNOCENT_EXTRA"));
    }

    #[test]
    fn is_safe_env_combines_allow_and_deny() {
        assert!(is_safe_env("PATH", "/usr/bin"));
        assert!(is_safe_env("cargo_home", "/h/.cargo")); // case-insensitive
        assert!(!is_safe_env("FOO", "bar")); // not allowlisted
        assert!(!is_safe_env("PATH", "contains_PRIVATE_x")); // value denied
        assert!(!is_safe_env("API_KEY", "x")); // name denied
    }

    #[test]
    fn prune_path_filters_by_roots() {
        use std::path::PathBuf;
        let roots = vec![PathBuf::from("/usr"), PathBuf::from("/home/u/.bun")];
        let denied = vec![PathBuf::from("/tmp"), PathBuf::from("/home/u/ws")];
        let input = "/usr/bin:/home/u/.bun/bin:/etc/evil:/tmp/evil:/home/u/ws/bin:bin:.";
        let out = prune_path(input, Some(&roots), &denied);
        let parts: Vec<&str> = out.split(':').collect();
        assert_eq!(parts, ["/usr/bin", "/home/u/.bun/bin"]);

        // None = keep every absolute entry (raw-host mode).
        let out = prune_path(input, None, &denied);
        let parts: Vec<&str> = out.split(':').collect();
        assert_eq!(parts, ["/usr/bin", "/home/u/.bun/bin", "/etc/evil"]);
    }

    #[test]
    fn path_gains_dev_bin_dirs() {
        // A GUI-launched app's PATH is minimal — discovered dev dirs are
        // appended, existing entries keep their order, nothing repeats.
        let mut out = sanitize_env(&[]);
        apply_environment_policy(
            &mut out,
            &crate::plan::EnvironmentPolicy::DevToolchain,
            None,
            &[],
        );
        let path = out
            .iter()
            .find(|(n, _)| n == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let entries: Vec<&str> = path.split(':').collect();
        // No duplicates.
        assert_eq!(
            entries.len(),
            entries
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        // Whatever dev bins exist on this machine are present.
        if let Some(home) = dirs_home() {
            for rel in [".bun/bin", ".volta/bin", ".cargo/bin", ".local/bin"] {
                let p = home.join(rel);
                if p.is_dir() {
                    let s = p.to_string_lossy();
                    assert!(entries.contains(&s.as_ref()), "PATH missing {s}: {path}");
                }
            }
        }
        // Toolchain var injection only when the dir exists and var unset.
        let mut out2 = sanitize_env(&[]);
        apply_environment_policy(
            &mut out2,
            &crate::plan::EnvironmentPolicy::DevToolchain,
            None,
            &[],
        );
        for (var, rel) in TOOLCHAIN_VAR_DEFAULTS {
            if std::env::var_os(var).is_some() {
                continue; // host set it — sanitize keeps host value
            }
            let dir = dirs_home().unwrap().join(rel);
            let present = out2.iter().any(|(n, _)| n == *var);
            assert_eq!(present, dir.exists(), "{var} injected wrongly");
        }
    }

    #[test]
    fn minimal_policy_skips_dev_bins() {
        // `Minimal` must not grow PATH or inject toolchain vars — the
        // environment decision lives in the plan, not the sanitizer.
        std::env::set_var("PATH", "/usr/bin:/bin");
        let mut out = sanitize_env(&[]);
        apply_environment_policy(
            &mut out,
            &crate::plan::EnvironmentPolicy::Minimal,
            None,
            &[],
        );
        let path = out
            .iter()
            .find(|(n, _)| n == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert_eq!(
            path, "/usr/bin:/bin",
            "Minimal must not add dev bins: {path}"
        );
    }
}
