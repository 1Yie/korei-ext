#![cfg(all(feature = "sandbox", unix))]

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agent_capabilities::{LinkedRoot, LinkedRoots, RootAccess, WorkspaceCtx};
use agent_sandbox::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
use agent_tool::{ToolContext, ToolResult};
use agent_tools_fs::commit::{WriteObserver, WriteObserverSlot};
use agent_tools_fs::{apply_patch, fs_patch, fs_read, grep, list_dir};
use serde_json::json;

#[derive(Default)]
struct Ctx(agent_tool::Extensions);
impl ToolContext for Ctx {
    fn extensions(&self) -> &agent_tool::Extensions {
        &self.0
    }
    fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
        &mut self.0
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    source: PathBuf,
    linked: PathBuf,
    snapshot: WorkspaceSnapshot,
    ctx: Arc<Ctx>,
    grants: Arc<LinkedRoots>,
}

fn fixture() -> Fixture {
    fixture_with(|_| {})
}

fn fixture_with(setup: impl FnOnce(&Path)) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("source");
    let linked = base.join("linked");
    let storage = base.join("storage");
    for path in [&source, &linked, &storage] {
        std::fs::create_dir(path).unwrap();
    }
    std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(source.join("file.rs"), "pub fn before() {}\n").unwrap();
    std::fs::write(linked.join("linked.txt"), "linked before\n").unwrap();
    std::fs::write(source.join(".gitignore"), "ignored.txt\n!kept.txt\n").unwrap();
    std::fs::write(source.join(".ignore"), "also-ignored.txt\n").unwrap();
    for path in ["ignored.txt", "also-ignored.txt", "kept.txt", "visible.txt"] {
        std::fs::write(source.join(path), "needle\n").unwrap();
    }
    std::fs::create_dir_all(source.join(".git/info")).unwrap();
    std::fs::write(source.join(".git/info/exclude"), "excluded.txt\n").unwrap();
    std::fs::write(source.join("excluded.txt"), "needle\n").unwrap();
    std::fs::create_dir(source.join("nested")).unwrap();
    std::fs::write(source.join("nested/file.txt"), "needle\n").unwrap();
    setup(&source);
    let snapshot = WorkspaceSnapshot::prepare(
        &[source.clone(), linked.clone()],
        &storage,
        SnapshotBudget {
            max_bytes: 8192,
            max_entries: 64,
            max_depth: 8,
        },
        SnapshotPreference::PrivateCopy,
    )
    .unwrap();
    let lease = snapshot.lease().unwrap();
    let primary = lease.roots().next().unwrap();
    let mut ctx = Ctx::default().with_workspace(lease.working_root(primary).unwrap());
    let grants = Arc::new(LinkedRoots::default());
    grants.set(vec![LinkedRoot {
        path: linked.clone(),
        access: RootAccess::ReadWrite,
    }]);
    ctx.install_linked_roots(grants.clone());
    ctx.install_workspace_lease(lease).unwrap();
    Fixture {
        _temp: temp,
        source,
        linked,
        snapshot,
        ctx: Arc::new(ctx),
        grants,
    }
}

async fn apply(result: ToolResult) {
    let commit = result.commit.unwrap();
    (commit.verify)().unwrap();
    commit.apply.await.unwrap();
}

#[tokio::test]
async fn host_ignore_configuration_matches_native_in_isolated_process() {
    const CHILD: &str = "KOREI_FS_IGNORE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut failures = Vec::new();
        for mode in [
            "xdg",
            "excludes-file",
            "relative",
            "tilde",
            "xdg-config",
            "global-override",
            "system",
            "git-worktree",
            "prepared-origin",
            "prepared-local",
            "prepared-host-rejected",
        ] {
            let config = tempfile::tempdir().unwrap();
            let home = config.path().join("home");
            let xdg = config.path().join("xdg");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(xdg.join("git")).unwrap();
            let global = home.join("global-ignore");
            std::fs::write(
                &global,
                "global.txt\n!also-ignored.txt\n!parent-ignore.txt\n!.whitelisted.txt\n",
            )
            .unwrap();
            if mode == "xdg" {
                std::fs::copy(&global, xdg.join("git/ignore")).unwrap();
            } else {
                let path = match mode {
                    "relative" => "home/global-ignore".to_owned(),
                    "tilde" => "~/global-ignore".to_owned(),
                    _ => global.display().to_string(),
                };
                let config_path = match mode {
                    "xdg-config" => xdg.join("git/config"),
                    "global-override" => config.path().join("override"),
                    "system" => config.path().join("system"),
                    _ => home.join(".gitconfig"),
                };
                std::fs::write(config_path, format!("[core]\nexcludesFile = {path}\n")).unwrap();
            }
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "host_ignore_configuration_matches_native_in_isolated_process",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &xdg)
                .current_dir(config.path())
                .env_remove("GIT_CONFIG_GLOBAL")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env(
                    "GIT_CONFIG_SYSTEM",
                    config.path().join("absent-system-config"),
                );
            if mode == "global-override" {
                command.env("GIT_CONFIG_GLOBAL", "override");
            }
            if mode == "system" {
                command.env_remove("GIT_CONFIG_NOSYSTEM");
                command.env("GIT_CONFIG_SYSTEM", config.path().join("system"));
            }
            let output = command.output().unwrap();
            if !output.status.success() {
                failures.push(format!(
                    "mode={mode}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        return;
    }
    let mode = std::env::var(CHILD).unwrap();
    let global = PathBuf::from(std::env::var_os("HOME").unwrap()).join("global-ignore");
    let f = fixture_with(|source| {
        if mode == "git-worktree" {
            let common = source.parent().unwrap().join("git-common");
            let gitdir = common.join("worktrees/probe");
            std::fs::create_dir_all(&gitdir).unwrap();
            std::fs::create_dir(common.join("info")).unwrap();
            std::fs::write(gitdir.join("commondir"), "../..\n").unwrap();
            std::fs::write(common.join("info/exclude"), "excluded.txt\n").unwrap();
            std::fs::remove_dir_all(source.join(".git")).unwrap();
            std::fs::write(
                source.join(".git"),
                format!("gitdir: {}\n", gitdir.display()),
            )
            .unwrap();
        }
        std::fs::write(source.join(".whitelisted.txt"), "needle\n").unwrap();
        std::fs::write(
            source.join(".global-ignore"),
            std::fs::read(&global).unwrap(),
        )
        .unwrap();
        std::fs::write(
            source.join(".gitconfig"),
            format!("[core]\nexcludesFile = {}\n", global.display()),
        )
        .unwrap();
    });
    let parent = f.source.parent().unwrap();
    std::fs::write(parent.join(".ignore"), "parent-ignore.txt\n").unwrap();
    std::fs::write(
        parent.join(".gitignore"),
        "/linked/parent-git.txt\n/source/visible.txt\n",
    )
    .unwrap();
    let native = Arc::new(Ctx::default().with_workspace(&f.source));
    let io = f.ctx.workspace_io().unwrap();
    if mode.starts_with("prepared-") {
        std::env::set_var("HOME", &f.source);
        std::env::set_var("XDG_CONFIG_HOME", f.source.join(".config"));
        std::fs::write(
            f.source.join(".gitconfig"),
            "[core]\nexcludesFile = source-only\n",
        )
        .unwrap();
        if mode == "prepared-local" {
            io.stage_write(Path::new(".gitconfig"))
                .unwrap()
                .apply(
                    Some(
                        format!(
                            "[core]\nexcludesFile = {}\n",
                            f.source.join(".global-ignore").display()
                        )
                        .as_bytes(),
                    ),
                    false,
                )
                .unwrap();
        }
        if mode == "prepared-host-rejected" {
            let other = global.with_file_name("other-ignore");
            std::fs::write(&other, "visible.txt\n").unwrap();
            io.stage_write(Path::new(".gitconfig"))
                .unwrap()
                .apply(
                    Some(format!("[core]\nexcludesFile = {}\n", other.display()).as_bytes()),
                    false,
                )
                .unwrap();
            let error = (list_dir::spec().exec)(json!({"path":"."}), f.ctx.clone())
                .await
                .unwrap_err();
            assert!(error.to_string().contains("cannot authorize"));
            return;
        }
    }
    // Root .gitignore bytes are deliberately different from the source tree.
    std::fs::write(f.source.join(".gitignore"), "visible.txt\n").unwrap();
    let mut failures = Vec::new();
    for (relative, working) in [(".", "."), ("linked", f.linked.to_str().unwrap())] {
        let source = if relative == "." {
            &f.source
        } else {
            &f.linked
        };
        for name in ["global.txt", "parent-ignore.txt", "parent-git.txt"] {
            std::fs::write(source.join(name), "needle\n").unwrap();
            let path = io.resolve(&Path::new(working).join(name), true).unwrap();
            std::fs::write(path, "needle\n").unwrap();
        }
        for include_hidden in [false, true] {
            let native_ctx = if relative == "." {
                // Restore only for the comparison, then poison the ambient copy.
                std::fs::write(f.source.join(".gitignore"), "ignored.txt\n!kept.txt\n").unwrap();
                native.clone()
            } else {
                Arc::new(Ctx::default().with_workspace(source))
            };
            let args = json!({"path":".", "depth":3, "include_hidden":include_hidden});
            let saved_config = std::fs::read(f.source.join(".gitconfig")).unwrap();
            if mode.starts_with("prepared-") {
                std::fs::write(
                    f.source.join(".gitconfig"),
                    io.read(Path::new(".gitconfig")).unwrap(),
                )
                .unwrap();
            }
            let expected = (list_dir::spec().exec)(args.clone(), native_ctx)
                .await
                .unwrap();
            std::fs::write(f.source.join(".gitconfig"), saved_config).unwrap();
            if relative == "." {
                std::fs::write(f.source.join(".gitignore"), "visible.txt\n").unwrap();
            }
            let actual = (list_dir::spec().exec)(
                json!({"path":working, "depth":3, "include_hidden":include_hidden}),
                f.ctx.clone(),
            )
            .await
            .unwrap();
            let actual = actual.content.replace(f.linked.to_str().unwrap(), ".");
            if actual != expected.content {
                failures.push(format!(
                    "root={relative}, hidden={include_hidden}\nleased: {actual}\nnative: {}",
                    expected.content
                ));
            }
            assert!(!expected.content.contains("global.txt"));
            assert!(!expected.content.contains("parent-ignore.txt"));
            assert_eq!(expected.content.contains("parent-git.txt"), relative == ".");
            if relative == "." {
                assert!(expected.content.contains(".whitelisted.txt"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn all_tools_use_private_bytes_and_ignore_files_and_stage_every_write() {
    let f = fixture();
    let io = f.ctx.workspace_io().unwrap();
    let native = Arc::new(Ctx::default().with_workspace(&f.source));
    for include_hidden in [false, true] {
        let args = json!({"path":".", "depth":3, "include_hidden":include_hidden});
        let expected = (list_dir::spec().exec)(args.clone(), native.clone())
            .await
            .unwrap();
        let actual = (list_dir::spec().exec)(args, f.ctx.clone()).await.unwrap();
        assert_eq!(actual.content, expected.content);
    }
    std::fs::write(f.source.join("file.rs"), "ambient\n").unwrap();
    std::fs::write(f.source.join(".gitignore"), "visible.txt\n").unwrap();
    let read = (fs_read::spec().exec)(json!({"path":"file.rs", "mode":"range"}), f.ctx.clone())
        .await
        .unwrap();
    assert!(read.content.contains("pub fn before()"), "{}", read.content);
    let outline =
        (fs_read::spec().exec)(json!({"path":"file.rs", "mode":"outline"}), f.ctx.clone())
            .await
            .unwrap();
    assert!(outline.content.contains("before"), "{}", outline.content);
    let listed = (list_dir::spec().exec)(json!({"path":".", "depth":3}), f.ctx.clone())
        .await
        .unwrap();
    for expected in ["file.rs", "visible.txt", "nested/file.txt", "kept.txt"] {
        assert!(listed.content.contains(expected), "{}", listed.content);
    }
    for excluded in ["ignored.txt", "also-ignored.txt", "excluded.txt"] {
        assert!(!listed.content.contains(excluded), "{}", listed.content);
    }
    let hits = (grep::spec().exec)(json!({"pattern":"needle"}), f.ctx.clone())
        .await
        .unwrap();
    assert!(hits.content.contains("visible.txt:1"), "{}", hits.content);
    assert!(!hits.content.contains("ignored.txt"), "{}", hits.content);
    assert!(!hits.content.contains("excluded.txt"), "{}", hits.content);
    let linked = (grep::spec().exec)(
        json!({"path":f.linked, "pattern":"before", "glob":"*.txt"}),
        f.ctx.clone(),
    )
    .await
    .unwrap();
    assert!(
        linked
            .content
            .contains(&format!("{}/linked.txt:1", f.linked.display())),
        "{}",
        linked.content
    );
    let patch = (fs_patch::spec().exec)(
        json!({
            "path":"file.rs", "search":"before", "replace":"after"
        }),
        f.ctx.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        io.read_to_string(Path::new("file.rs")).unwrap(),
        "pub fn before() {}\n"
    );
    apply(patch).await;
    assert_eq!(
        io.read_to_string(Path::new("file.rs")).unwrap(),
        "pub fn after() {}\n"
    );
    let result = (apply_patch::spec().exec)(json!({"patch":"*** Begin Patch\n*** Add File: new/deep.txt\n+created\n*** Update File: file.rs\n*** Move to: moved.rs\n@@\n-pub fn after() {}\n+pub fn moved() {}\n*** Delete File: visible.txt\n*** End Patch"}), f.ctx.clone()).await.unwrap();
    assert_eq!(io.read_optional(Path::new("new/deep.txt")).unwrap(), None);
    apply(result).await;
    assert_eq!(
        io.read_to_string(Path::new("new/deep.txt")).unwrap(),
        "created\n"
    );
    assert_eq!(
        io.read_to_string(Path::new("moved.rs")).unwrap(),
        "pub fn moved() {}\n"
    );
    assert_eq!(io.read_optional(Path::new("file.rs")).unwrap(), None);
    assert_eq!(io.read_optional(Path::new("visible.txt")).unwrap(), None);
    assert_eq!(
        std::fs::read_to_string(f.source.join("file.rs")).unwrap(),
        "ambient\n"
    );
    assert!(!f.source.join("new").exists());
}

#[tokio::test]
async fn stale_preimages_live_grants_and_aliases_refuse_without_ambient_effects() {
    let f = fixture();
    let io = f.ctx.workspace_io().unwrap();
    let patch = json!({"path":"file.rs", "search":"before", "replace":"after"});
    let result = (fs_patch::spec().exec)(patch.clone(), f.ctx.clone())
        .await
        .unwrap();
    let file = io.resolve(Path::new("file.rs"), true).unwrap();
    std::fs::write(&file, "changed\n").unwrap();
    let commit = result.commit.unwrap();
    assert!((commit.verify)().is_err());
    assert!(commit.apply.await.is_err());
    let linked = f.linked.join("linked.txt").display().to_string();
    let result = (fs_patch::spec().exec)(
        json!({"path":linked, "search":"before", "replace":"after"}),
        f.ctx.clone(),
    )
    .await
    .unwrap();
    f.grants.set(vec![LinkedRoot {
        path: f.linked.clone(),
        access: RootAccess::Read,
    }]);
    let commit = result.commit.unwrap();
    assert!((commit.verify)().is_err());
    assert!(commit.apply.await.is_err());
    std::fs::remove_file(&file).unwrap();
    symlink(f.source.join("file.rs"), &file).unwrap();
    assert!(
        (fs_read::spec().exec)(json!({"path":"file.rs"}), f.ctx.clone())
            .await
            .is_err()
    );
    assert!((list_dir::spec().exec)(json!({}), f.ctx.clone())
        .await
        .is_err());
    assert!(
        (grep::spec().exec)(json!({"pattern":"before"}), f.ctx.clone())
            .await
            .is_err()
    );
    assert!((fs_patch::spec().exec)(patch, f.ctx.clone()).await.is_err());
    assert!((apply_patch::spec().exec)(
        json!({"patch":"*** Begin Patch\n*** Delete File: file.rs\n*** End Patch"}),
        f.ctx.clone()
    )
    .await
    .is_err());
    assert_eq!(
        std::fs::read_to_string(f.source.join("file.rs")).unwrap(),
        "pub fn before() {}\n"
    );
    assert_eq!(
        std::fs::read_to_string(f.linked.join("linked.txt")).unwrap(),
        "linked before\n"
    );
}

struct BlockingObserver {
    started: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl WriteObserver for BlockingObserver {
    fn on_write(&self, _: PathBuf, old: Option<Vec<u8>>, new: Vec<u8>) {
        assert_eq!(old.as_deref(), Some(b"pub fn before() {}\n".as_slice()));
        assert_eq!(new, b"pub fn after() {}\n");
        self.started.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

#[tokio::test]
async fn dropped_commit_and_cancelled_waiter_keep_actual_io_alive_through_observer() {
    let patch = json!({"path":"file.rs", "search":"before", "replace":"after"});
    for verify_only in [false, true] {
        let mut pending = fixture();
        let result = (fs_patch::spec().exec)(patch.clone(), pending.ctx.clone())
            .await
            .unwrap();
        drop(pending.ctx);
        assert!(pending.snapshot.seal().is_err());
        if verify_only {
            let commit = result.commit.unwrap();
            drop(commit.apply);
            assert!(pending.snapshot.seal().is_err());
            (commit.verify)().unwrap();
        } else {
            drop(result);
        }
        pending.snapshot.seal().unwrap();
    }
    let mut f = fixture();
    let (started, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    Arc::get_mut(&mut f.ctx)
        .unwrap()
        .extensions_mut()
        .insert_shared(Arc::new(WriteObserverSlot(Arc::new(BlockingObserver {
            started,
            release: Mutex::new(wait),
        }))));
    let result = (fs_patch::spec().exec)(patch, f.ctx.clone()).await.unwrap();
    let commit = result.commit.unwrap();
    (commit.verify)().unwrap();
    let weak = Arc::downgrade(&f.ctx);
    let waiter = tokio::spawn(commit.apply);
    tokio::task::spawn_blocking(move || ready.recv().unwrap())
        .await
        .unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    drop(f.ctx);
    assert!(
        f.snapshot.seal().is_err(),
        "the blocking effect still owns the lease"
    );
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if weak.upgrade().is_none() && f.snapshot.seal().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the released write did not drop its snapshot lease");
    assert_eq!(
        std::fs::read_to_string(f.source.join("file.rs")).unwrap(),
        "pub fn before() {}\n"
    );
}
