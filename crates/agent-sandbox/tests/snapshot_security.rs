#![cfg(unix)]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use agent_sandbox::snapshot::*;

fn budget() -> SnapshotBudget {
    SnapshotBudget {
        max_bytes: 8 * 1024 * 1024,
        max_entries: 128,
        max_depth: 8,
    }
}

#[test]
fn checked_rejection_preserves_the_entire_batch_and_private_bytes() {
    let (_temp, source, storage) = setup();
    fs::write(source.join("file"), b"source").unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let old = snapshot.lease().unwrap();
    let root = old.roots().next().unwrap();
    old.write_file(root, Path::new("file"), b"private").unwrap();
    let before = format!("{:?}", snapshot.stats());
    let candidates: Vec<_> = ["extra", "another"]
        .into_iter()
        .map(|name| {
            let path = source.parent().unwrap().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("file"), b"candidate").unwrap();
            path
        })
        .collect();
    let mut checked = 0;
    assert!(snapshot
        .append_roots_checked(&candidates, |_, _| {
            checked += 1;
            if checked == 2 {
                anyhow::bail!("injected rejection");
            }
            Ok(())
        })
        .is_err());
    assert_eq!(checked, 2);
    assert_eq!(format!("{:?}", snapshot.stats()), before);
    assert_eq!(snapshot.lease().unwrap().roots().count(), 1);
    assert_eq!(old.roots().count(), 1);
    let mut bytes = Vec::new();
    old.read_file(root, Path::new("file"))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"private");
    assert_eq!(fs::read(source.join("file")).unwrap(), b"source");
    assert_eq!(snapshot.append_roots(&candidates).unwrap().len(), 2);
}

#[cfg(target_os = "macos")]
fn worker_request(mut read_only: Vec<std::path::PathBuf>) -> agent_sandbox::spawn::IsolatedSpawn {
    use agent_sandbox::spawn::*;
    if cfg!(target_os = "macos") {
        for path in ["/usr/lib", "/System/Library"] {
            let path = std::path::PathBuf::from(path);
            if !read_only.contains(&path) {
                read_only.push(path);
            }
        }
    }
    IsolatedSpawn {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), "IFS= read -r finish".into()],
        linux_launcher: None,
        linux_cgroup_parent: None,
        root: None,
        kind: ExecutionKind::Worker,
        read_only,
        deny_read: vec![],
        deny_write: vec![],
        env: vec![],
        max_memory_bytes: 64 * 1024 * 1024,
        max_processes: 1,
        memory_enforcement: MemoryEnforcement::MonitoredRss,
        tool_policy: None,
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn retained_owners_block_admission_until_actual_quiescence() {
    use agent_sandbox::spawn::{spawn_isolated, spawn_worker_in_view};
    use std::sync::Arc;
    for in_view in [false, true] {
        let (_temp, source, storage) = setup();
        let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
        let candidate = source.parent().unwrap().join("candidate");
        fs::create_dir(&candidate).unwrap();
        let view = Arc::new(snapshot.lease().unwrap());
        let mut request = worker_request(vec![candidate.clone()]);
        if !in_view {
            request.root = Some(view.roots().next().unwrap());
        }
        let mut child = if in_view {
            spawn_worker_in_view(
                WorkerScope::prepare(&storage).unwrap(),
                view.clone(),
                &request,
            )
        } else {
            spawn_isolated(view.clone(), &request)
        }
        .unwrap();
        let grants = snapshot.effective_grants();
        assert_eq!(grants.len(), 1);
        assert!(Arc::ptr_eq(&grants[0], &child.effective_grants().unwrap()));
        let mut callback_called = false;
        assert!(snapshot
            .append_roots_checked(&[candidate.clone()], |_, _| {
                callback_called = true;
                Ok(())
            })
            .is_err());
        assert!(
            !callback_called,
            "an empty host blocker list cannot release an owner"
        );
        child.kill().await.unwrap();
        assert!(grants[0].is_quiescent());
        snapshot.append_roots(&[candidate]).unwrap();
    }
}

#[cfg(target_os = "macos")]
#[test]
fn startup_during_checked_commit_validates_all_current_roots() {
    use agent_sandbox::spawn::{spawn_isolated, spawn_worker_in_view};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;
    for in_view in [false, true] {
        for grant_working in [false, true] {
            let (_temp, source, storage) = setup();
            fs::write(source.join("file"), b"old").unwrap();
            let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
            let old = Arc::new(snapshot.lease().unwrap());
            let extra = source.parent().unwrap().join("extra");
            fs::create_dir(&extra).unwrap();
            let (attempting, attempted) = mpsc::sync_channel(1);
            let (finished, result) = mpsc::sync_channel(1);
            let mut thread = None;
            let added = snapshot
                .append_roots_checked(&[extra.clone()], |candidate, working| {
                    let mut request = worker_request(vec![if grant_working {
                        working.to_owned()
                    } else {
                        candidate.to_owned()
                    }]);
                    let view = old.clone();
                    if !in_view {
                        request.root = Some(view.roots().next().unwrap());
                    }
                    let worker = WorkerScope::prepare(&storage).unwrap();
                    let attempting = attempting.clone();
                    let finished = finished.clone();
                    thread = Some(std::thread::spawn(move || {
                        attempting.send(()).unwrap();
                        let result = if in_view {
                            spawn_worker_in_view(worker, view, &request)
                        } else {
                            spawn_isolated(view, &request)
                        };
                        finished
                            .send(result.map(|_| ()).map_err(|error| format!("{error:#}")))
                            .unwrap();
                    }));
                    attempted.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert!(matches!(
                        result.recv_timeout(Duration::from_millis(30)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ));
                    Ok(())
                })
                .unwrap();
            let error = result
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap_err();
            thread.unwrap().join().unwrap();
            assert!(error.contains("source workspace"), "{error}");
            assert!(
                snapshot.effective_grants().is_empty(),
                "pre-thread failure leaked a starting owner"
            );
            assert!(old.working_root(added[0]).is_err());
            assert!(snapshot.lease().unwrap().working_root(added[0]).is_ok());
            let mut bytes = Vec::new();
            old.read_file(old.roots().next().unwrap(), Path::new("file"))
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, b"old");
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn worker_in_view_cannot_read_or_write_snapshot_files() {
    use agent_sandbox::spawn::spawn_worker_in_view;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    let (_temp, source, storage) = setup();
    fs::write(source.join("file"), b"source").unwrap();
    let snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let view = Arc::new(snapshot.lease().unwrap());
    let working = view.working_root(view.roots().next().unwrap()).unwrap();
    let mut request = worker_request(vec![]);
    request.args = vec![
        "-c".into(),
        "for path in \"$@\"; do if IFS= read -r value < \"$path\"; then exit 11; fi; if printf overwritten > \"$path\"; then exit 12; fi; done; printf denied".into(),
        "worker".into(),
        source.join("file").into_os_string(),
        working.join("file").into_os_string(),
    ];
    let mut child = spawn_worker_in_view(
        WorkerScope::prepare(&storage).unwrap(),
        view.clone(),
        &request,
    )
    .unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut bytes = Vec::new();
    let (status, read) = tokio::join!(child.wait(), output.read_to_end(&mut bytes));
    read.unwrap();
    assert!(status.unwrap().success());
    assert_eq!(bytes, b"denied");
    assert_eq!(fs::read(source.join("file")).unwrap(), b"source");
    assert_eq!(fs::read(working.join("file")).unwrap(), b"source");
}

#[test]
fn retained_snapshot_reopens_private_bytes_and_refuses_a_replaced_directory() {
    let (_temp, source, storage) = setup();
    fs::write(source.join("file"), b"source").unwrap();
    let snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    lease
        .write_file(root, Path::new("file"), b"private")
        .unwrap();
    drop(lease);
    let retained = snapshot.retain_private().unwrap();
    drop(snapshot);
    assert_eq!(
        fs::read(retained.roots[0].working.join("file")).unwrap(),
        b"private"
    );
    let mut reopened = WorkspaceSnapshot::reopen(&retained).unwrap();
    let lease = reopened.lease().unwrap();
    let mut bytes = Vec::new();
    lease
        .read_file(lease.roots().next().unwrap(), Path::new("file"))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"private");
    drop(lease);
    assert!(reopened
        .seal()
        .unwrap()
        .iter()
        .any(|change| change.path == Path::new("file")));
    drop(reopened);
    let mut forged = retained.clone();
    forged.container_identity = (0, 1);
    assert!(WorkspaceSnapshot::discard_retained(&forged).is_err());
    assert!(retained.container.exists());
    WorkspaceSnapshot::discard_retained(&retained).unwrap();
    assert!(!retained.container.exists());
}

fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("source");
    let storage = root.join("storage");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&storage).unwrap();
    fs::set_permissions(&storage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(source.join("data"), vec![0x6d; 1024 * 1024]).unwrap();
    (temp, source, storage)
}

fn prepare(source: &Path, storage: &Path, preference: SnapshotPreference) -> WorkspaceSnapshot {
    WorkspaceSnapshot::prepare(&[source.to_owned()], storage, budget(), preference).unwrap()
}

#[test]
fn native_or_explicit_copy_isolates_both_directions_and_preserves_bytes() {
    for preference in [
        SnapshotPreference::NativePreferred,
        SnapshotPreference::PrivateCopy,
    ] {
        let (_temp, source, storage) = setup();
        let snapshot = prepare(&source, &storage, preference);
        let stats = snapshot.stats();
        assert_eq!(stats.prepared_bytes, 2 * 1024 * 1024);
        assert_eq!(stats.native_cow_files + stats.private_copy_files, 2);
        if preference == SnapshotPreference::PrivateCopy {
            assert_eq!(stats.private_copy_files, 2);
        }
        #[cfg(target_os = "macos")]
        if preference == SnapshotPreference::NativePreferred {
            assert_eq!(stats.native_cow_files, 2);
        }
        let lease = snapshot.lease().unwrap();
        let root = lease.roots().next().unwrap();
        let original = fs::read(source.join("data")).unwrap();
        lease
            .write_file(root, Path::new("data"), b"private write")
            .unwrap();
        assert_eq!(fs::read(source.join("data")).unwrap(), original);
        fs::write(source.join("data"), b"host write").unwrap();
        let mut private = Vec::new();
        lease
            .read_file(root, Path::new("data"))
            .unwrap()
            .read_to_end(&mut private)
            .unwrap();
        assert_eq!(private, b"private write");
        assert_eq!(
            lease.map_source(&source.join("data")).unwrap(),
            (root, Path::new("data").to_owned())
        );
        assert!(lease.map_source(storage.join("other").as_path()).is_err());
    }
}

#[test]
fn preparation_budgets_fail_without_partial_storage_or_host_changes() {
    for limits in [
        SnapshotBudget {
            max_bytes: 1024,
            ..budget()
        },
        SnapshotBudget {
            max_entries: 1,
            ..budget()
        },
        SnapshotBudget {
            max_depth: 1,
            ..budget()
        },
    ] {
        let (_temp, source, storage) = setup();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/deep"), b"x").unwrap();
        assert!(WorkspaceSnapshot::prepare(
            &[source.clone()],
            &storage,
            limits,
            SnapshotPreference::PrivateCopy
        )
        .is_err());
        assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
        assert_eq!(
            fs::metadata(source.join("data")).unwrap().len(),
            1024 * 1024
        );
    }
}

#[test]
fn appended_roots_keep_old_leases_bounded_and_publish_in_one_snapshot() {
    let (_temp, source, storage) = setup();
    fs::write(source.join("file"), b"before").unwrap();
    let extra = source.parent().unwrap().join("extra");
    fs::create_dir(&extra).unwrap();
    fs::write(extra.join("file"), b"second").unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let old = snapshot.lease().unwrap();
    let first = old.roots().next().unwrap();
    let borrowed = old.working_root(first).unwrap();
    let mut file = old.read_file(first, Path::new("file")).unwrap();
    let added = snapshot.append_roots(&[extra.clone()]).unwrap();
    let current = snapshot.lease().unwrap();
    let second = added[0];
    let private = current.working_root(second).unwrap();
    assert_eq!(borrowed, current.working_root(first).unwrap());
    assert_eq!(old.roots().collect::<Vec<_>>(), vec![first]);
    assert_eq!(current.roots().collect::<Vec<_>>(), vec![first, second]);
    assert!(old.working_root(second).is_err());
    assert!(old.map_source(&extra.join("file")).is_err());
    assert!(old.read_file(second, Path::new("file")).is_err());
    assert!(old
        .write_file(second, Path::new("file"), b"ungranted")
        .is_err());
    for path in [extra.join("file"), private.join("file")] {
        assert!(old.read_ignore_config(&path, |_| Ok(None)).is_err());
        assert!(old
            .read_ignore_config_baseline(&path, |_| Ok(None))
            .is_err());
    }
    let third = source.parent().unwrap().join("third");
    fs::create_dir(&third).unwrap();
    let third = snapshot.append_roots(&[third]).unwrap()[0];
    let newest = snapshot.lease().unwrap();
    assert_eq!(
        newest.roots().collect::<Vec<_>>(),
        vec![first, second, third]
    );
    assert_eq!(current.roots().collect::<Vec<_>>(), vec![first, second]);
    assert!(current.working_root(third).is_err());
    assert_eq!(borrowed, newest.working_root(first).unwrap());
    drop(newest);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"before");
    let clone = file.try_clone().unwrap();
    current
        .write_file(first, Path::new("file"), b"first edit")
        .unwrap();
    current
        .write_file(second, Path::new("file"), b"second edit")
        .unwrap();
    assert_eq!(fs::read(source.join("file")).unwrap(), b"before");
    assert_eq!(fs::read(extra.join("file")).unwrap(), b"second");
    drop(current);
    drop(old);
    drop(file);
    assert!(snapshot.seal().is_err());
    drop(clone);
    assert_eq!(snapshot.seal().unwrap().len(), 2);
    assert!(snapshot.append_roots(&[extra.clone()]).is_err());
    let report = snapshot.publish(|| false).unwrap();
    assert!(report.conflicts.is_empty());
    assert_eq!(report.applied.len(), 2);
    assert_eq!(fs::read(source.join("file")).unwrap(), b"first edit");
    assert_eq!(fs::read(extra.join("file")).unwrap(), b"second edit");
}

#[test]
fn append_failure_preserves_roots_budget_and_private_material() {
    for bytes_budget in [true, false] {
        let (_temp, source, storage) = setup();
        fs::remove_file(source.join("data")).unwrap();
        fs::write(source.join("file"), b"aa").unwrap();
        let extra = source.parent().unwrap().join("extra");
        fs::create_dir(&extra).unwrap();
        fs::write(extra.join("file"), b"bb").unwrap();
        let mut snapshot = WorkspaceSnapshot::prepare(
            &[source.clone()],
            &storage,
            SnapshotBudget {
                max_bytes: if bytes_budget { 6 } else { 100 },
                max_entries: if bytes_budget { 100 } else { 3 },
                max_depth: 8,
            },
            SnapshotPreference::PrivateCopy,
        )
        .unwrap();
        let lease = snapshot.lease().unwrap();
        let first = lease.roots().next().unwrap();
        let working = lease.working_root(first).unwrap().to_path_buf();
        let container = working.parent().unwrap();
        let names = || {
            let mut names: Vec<_> = fs::read_dir(container)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = names();
        let stats = snapshot.stats();
        let error = snapshot.append_roots(&[extra]).unwrap_err();
        assert!(error.to_string().contains("budget"), "{error:#}");
        assert_eq!(snapshot.stats(), stats);
        assert_eq!(names(), before);
        assert_eq!(snapshot.lease().unwrap().roots().count(), 1);
        for path in [
            source.as_path(),
            source.parent().unwrap(),
            storage.as_path(),
        ] {
            assert!(snapshot.append_roots(&[path.to_path_buf()]).is_err());
        }
        assert_eq!(fs::read(working.join("file")).unwrap(), b"aa");
        let small = source.parent().unwrap().join("small");
        fs::create_dir(&small).unwrap();
        if bytes_budget {
            fs::write(small.join("file"), b"x").unwrap();
        }
        let added = snapshot.append_roots(&[small]).unwrap();
        let current = snapshot.lease().unwrap();
        assert_eq!(current.roots().collect::<Vec<_>>(), vec![first, added[0]]);
        assert_eq!(lease.roots().count(), 1);
        assert_eq!(
            snapshot.stats().prepared_bytes,
            stats.prepared_bytes + if bytes_budget { 2 } else { 0 }
        );
        drop(current);
        drop(lease);
        assert!(snapshot.seal().unwrap().is_empty());
    }
}

#[test]
fn appended_root_identity_and_derived_files_keep_the_original_lifetime() {
    let (_temp, source, storage) = setup();
    let extra = source.parent().unwrap().join("extra");
    fs::create_dir(&extra).unwrap();
    fs::write(extra.join("file"), b"second").unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let added = snapshot.append_roots(&[extra]).unwrap();
    let lease = snapshot.lease().unwrap();
    let working = lease.working_root(added[0]).unwrap().to_path_buf();
    let mut file = lease.read_file(added[0], Path::new("file")).unwrap();
    let displaced = working.with_file_name("displaced");
    fs::rename(&working, &displaced).unwrap();
    fs::create_dir(&working).unwrap();
    fs::write(working.join("file"), b"substitute").unwrap();
    assert!(lease.read_file(added[0], Path::new("file")).is_err());
    drop(lease);
    drop(snapshot);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"second");
    assert!(displaced.exists());
    drop(file);
    assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
}

#[test]
fn links_special_files_and_overlapping_roots_fail_closed() {
    let (_temp, source, storage) = setup();
    let outside = storage.join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, source.join("escape")).unwrap();
    let snapshot = WorkspaceSnapshot::prepare(
        &[source.clone()],
        &storage,
        budget(),
        SnapshotPreference::PrivateCopy,
    )
    .unwrap();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap();
    assert!(working.join("data").is_file());
    assert!(!working.join("escape").exists());
    assert!(lease.read_file(root, Path::new("escape")).is_err());
    drop(lease);
    drop(snapshot);
    fs::remove_file(source.join("escape")).unwrap();
    fs::hard_link(&outside, source.join("hardlink")).unwrap();
    let snapshot = WorkspaceSnapshot::prepare(
        &[source.clone()],
        &storage,
        budget(),
        SnapshotPreference::PrivateCopy,
    )
    .unwrap();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    assert!(!lease.working_root(root).unwrap().join("hardlink").exists());
    assert!(lease.read_file(root, Path::new("hardlink")).is_err());
    drop(lease);
    drop(snapshot);
    fs::remove_file(source.join("hardlink")).unwrap();
    assert!(WorkspaceSnapshot::prepare(
        &[source.clone()],
        &source,
        budget(),
        SnapshotPreference::PrivateCopy
    )
    .is_err());
    assert!(WorkspaceSnapshot::prepare(
        &[source.clone(), source.clone()],
        &storage,
        budget(),
        SnapshotPreference::PrivateCopy
    )
    .is_err());
    fs::create_dir(source.join("recursive")).unwrap();
    fs::set_permissions(source.join("recursive"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(WorkspaceSnapshot::prepare(
        &[source.clone()],
        &source.join("recursive"),
        budget(),
        SnapshotPreference::PrivateCopy
    )
    .is_err());
}

#[test]
fn leased_file_access_never_truncates_an_escaped_symlink_or_hardlink() {
    let (_temp, source, storage) = setup();
    let snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap();
    symlink(source.join("data"), working.join("escape")).unwrap();
    assert!(lease
        .write_file(root, Path::new("escape"), b"destroy")
        .is_err());
    fs::hard_link(source.join("data"), working.join("hardlink")).unwrap();
    assert!(lease
        .write_file(root, Path::new("hardlink"), b"destroy")
        .is_err());
    assert!(lease
        .write_file(root, Path::new("../baseline-0/data"), b"destroy")
        .is_err());
    symlink(&source, working.join("parent")).unwrap();
    assert!(lease
        .write_file(root, Path::new("parent/data"), b"destroy")
        .is_err());
    assert!(lease.create_file(root, Path::new("parent/new")).is_err());
    assert_eq!(
        fs::metadata(source.join("data")).unwrap().len(),
        1024 * 1024
    );
}

#[test]
fn derived_files_keep_the_snapshot_unsealable_until_closed() {
    let (_temp, source, storage) = setup();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let mut writer = lease.create_file(root, Path::new("new")).unwrap();
    let reader = lease.read_file(root, Path::new("data")).unwrap();
    writer.write_all(b"preview").unwrap();
    let mut clone = writer.try_clone().unwrap();
    drop(lease);
    assert!(
        snapshot.seal().is_err(),
        "derived writer and reader outlive lease"
    );
    assert!(snapshot.try_seal().unwrap().is_none());
    drop(writer);
    assert!(snapshot.seal().is_err(), "derived reader outlives lease");
    drop(reader);
    assert!(snapshot.try_seal().unwrap().is_none());
    assert!(
        snapshot.seal().is_err(),
        "controlled clone outlives original handles"
    );
    clone.seek(SeekFrom::Start(0)).unwrap();
    clone.write_all(b"changed").unwrap();
    clone.sync_all().unwrap();
    assert_eq!(clone.metadata().unwrap().len(), 7);
    drop(clone);
    assert!(snapshot.try_seal().unwrap().is_some());
    snapshot.publish(|| false).unwrap();
    assert!(snapshot.try_seal().is_err());
    assert_eq!(fs::read(source.join("new")).unwrap(), b"changed");
}

#[test]
fn seal_requires_quiescence_and_publish_has_recoverable_preimages() {
    let (_temp, source, storage) = setup();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    lease
        .write_file(root, Path::new("data"), b"published")
        .unwrap();
    assert!(snapshot.seal().is_err());
    drop(lease);
    assert_eq!(snapshot.seal().unwrap().len(), 1);
    assert!(snapshot.lease().is_err());
    let report = snapshot.publish(|| false).unwrap();
    assert_eq!(report.applied.len(), 1);
    assert!(report.conflicts.is_empty());
    assert!(report.recovery_required.is_empty());
    assert_eq!(fs::read(source.join("data")).unwrap(), b"published");
    assert_eq!(
        fs::metadata(report.recovery_material[0].join("original"))
            .unwrap()
            .len(),
        1024 * 1024
    );
    snapshot.rollback().unwrap();
    assert_eq!(fs::read(source.join("data")).unwrap(), b"published");
    assert!(report.recovery_material[0].join("original").exists());
}

#[test]
fn failed_publication_keeps_sealed_or_requires_recovery_after_partial_changes() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "requires ordinary user permissions"
    );
    for partial in [false, true] {
        let (_temp, source, storage) = setup();
        fs::create_dir(source.join("locked")).unwrap();
        fs::write(source.join("locked/data"), b"original").unwrap();
        fs::set_permissions(source.join("locked"), fs::Permissions::from_mode(0o555)).unwrap();
        let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
        let lease = snapshot.lease().unwrap();
        let root = lease.roots().next().unwrap();
        let working = lease.working_root(root).unwrap();
        fs::write(working.join("locked/data"), b"replacement").unwrap();
        if partial {
            lease.write_file(root, Path::new("data"), b"first").unwrap();
        }
        drop(lease);
        snapshot.seal().unwrap();
        let report = snapshot.publish(|| false).unwrap();
        assert_eq!(report.applied.len(), usize::from(partial));
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(fs::read(source.join("locked/data")).unwrap(), b"original");
        if partial {
            assert_eq!(snapshot.state(), SnapshotState::RecoveryRequired);
            assert!(!report.recovery_required.is_empty());
            assert_eq!(report.recovery_material.len(), 1);
            assert_eq!(
                fs::metadata(report.recovery_material[0].join("original"))
                    .unwrap()
                    .len(),
                1024 * 1024
            );
            fs::write(source.join("data"), b"later user edit").unwrap();
            assert!(snapshot.publish(|| false).is_err());
            assert_eq!(fs::read(source.join("data")).unwrap(), b"later user edit");
        } else {
            assert_eq!(snapshot.state(), SnapshotState::Sealed);
            assert!(report.recovery_required.is_empty());
            assert!(report.recovery_material.is_empty());
        }
        fs::set_permissions(source.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn directory_modes_are_preserved_and_finalized_after_children() {
    let (_temp, source, storage) = setup();
    fs::create_dir(source.join("existing")).unwrap();
    fs::set_permissions(source.join("existing"), fs::Permissions::from_mode(0o750)).unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap();
    assert_eq!(
        fs::metadata(working.join("existing"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    fs::create_dir(working.join("existing/new")).unwrap();
    fs::write(working.join("existing/new/file"), b"child").unwrap();
    fs::set_permissions(
        working.join("existing/new"),
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    fs::set_permissions(working.join("existing"), fs::Permissions::from_mode(0o500)).unwrap();
    drop(lease);
    assert_eq!(snapshot.seal().unwrap().len(), 3);
    let report = snapshot.publish(|| false).unwrap();
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert!(report.recovery_required.is_empty());
    assert_eq!(report.applied.len(), 3);
    assert_eq!(snapshot.state(), SnapshotState::Published);
    for path in ["existing", "existing/new"] {
        assert_eq!(
            fs::metadata(source.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
    }
    assert_eq!(
        fs::read(source.join("existing/new/file")).unwrap(),
        b"child"
    );
    fs::set_permissions(source.join("existing"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        source.join("existing/new"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[test]
fn directory_mode_changes_conflict_with_concurrent_host_permissions() {
    let (_temp, source, storage) = setup();
    fs::create_dir(source.join("dir")).unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    fs::set_permissions(
        lease.working_root(root).unwrap().join("dir"),
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    drop(lease);
    assert_eq!(snapshot.seal().unwrap().len(), 1);
    fs::set_permissions(source.join("dir"), fs::Permissions::from_mode(0o750)).unwrap();
    let report = snapshot.publish(|| false).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    assert!(report.applied.is_empty());
    assert_eq!(snapshot.state(), SnapshotState::Sealed);
    assert_eq!(
        fs::metadata(source.join("dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
}

#[test]
fn cancellation_and_host_concurrent_content_change_leave_host_untouched() {
    let (_temp, source, storage) = setup();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    lease
        .write_file(root, Path::new("data"), b"private")
        .unwrap();
    drop(lease);
    snapshot.seal().unwrap();
    let report = snapshot.publish(|| true).unwrap();
    assert!(report.cancelled);
    assert!(report.applied.is_empty());
    assert!(report.recovery_material.is_empty());
    assert_eq!(snapshot.state(), SnapshotState::Sealed);
    fs::write(source.join("data"), b"concurrent user content").unwrap();
    let report = snapshot.publish(|| false).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    assert!(report.applied.is_empty());
    assert_eq!(
        fs::read(source.join("data")).unwrap(),
        b"concurrent user content"
    );
    assert!(report.recovery_material.is_empty());
}

#[test]
fn root_parent_and_target_identity_substitution_are_conflicts() {
    for substitution in ["root", "parent", "target", "type"] {
        let (_temp, source, storage) = setup();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), b"old").unwrap();
        let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
        let lease = snapshot.lease().unwrap();
        let root = lease.roots().next().unwrap();
        lease
            .write_file(root, Path::new("nested/file"), b"private")
            .unwrap();
        drop(lease);
        snapshot.seal().unwrap();
        match substitution {
            "root" => {
                fs::rename(&source, source.with_extension("original")).unwrap();
                fs::create_dir(&source).unwrap();
            }
            "parent" => {
                fs::rename(source.join("nested"), source.join("displaced")).unwrap();
                fs::create_dir(source.join("nested")).unwrap();
                fs::write(source.join("nested/file"), b"old").unwrap();
            }
            "target" => {
                fs::rename(source.join("nested/file"), source.join("nested/old")).unwrap();
                fs::write(source.join("nested/file"), b"old").unwrap();
            }
            "type" => {
                fs::remove_file(source.join("nested/file")).unwrap();
                fs::create_dir(source.join("nested/file")).unwrap();
            }
            _ => unreachable!(),
        }
        let report = snapshot.publish(|| false).unwrap();
        assert_eq!(report.conflicts.len(), 1, "{substitution}");
        assert!(report.applied.is_empty());
        assert!(report.recovery_material.is_empty());
    }
}

#[test]
fn partial_publish_keeps_applied_preimages_and_never_overwrites_later_user_changes() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (_temp, source, storage) = setup();
    fs::write(source.join("a"), b"original a").unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("nested/b"), b"original b").unwrap();
    fs::set_permissions(source.join("nested"), fs::Permissions::from_mode(0o555)).unwrap();
    let mut snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    fs::set_permissions(
        lease.working_root(root).unwrap().join("nested"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    lease
        .write_file(root, Path::new("a"), b"published a")
        .unwrap();
    lease
        .write_file(root, Path::new("nested/b"), b"unpublished b")
        .unwrap();
    drop(lease);
    snapshot.seal().unwrap();
    let report = snapshot.publish(|| false).unwrap();
    assert_eq!(report.applied.len(), 1);
    assert_eq!(report.recovery_required.len(), 1);
    assert_eq!(snapshot.state(), SnapshotState::RecoveryRequired);
    assert_eq!(fs::read(source.join("a")).unwrap(), b"published a");
    assert_eq!(fs::read(source.join("nested/b")).unwrap(), b"original b");
    let backup = report.recovery_material[0].join("original");
    assert_eq!(fs::read(&backup).unwrap(), b"original a");
    fs::write(source.join("a"), b"user edit after partial publish").unwrap();
    snapshot.rollback().unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"original a");
    assert_eq!(
        fs::read(source.join("a")).unwrap(),
        b"user edit after partial publish"
    );
    fs::set_permissions(source.join("nested"), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn native_unix_names_survive_without_lossy_conversion() {
    use std::os::unix::ffi::OsStringExt;
    let (_temp, source, storage) = setup();
    let name = std::ffi::OsString::from_vec(vec![b'f', 0xff]);
    fs::write(source.join(&name), b"native").unwrap();
    fs::set_permissions(source.join(&name), fs::Permissions::from_mode(0o750)).unwrap();
    let snapshot = prepare(&source, &storage, SnapshotPreference::PrivateCopy);
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap();
    assert_eq!(fs::read(working.join(&name)).unwrap(), b"native");
    assert_eq!(
        fs::metadata(working.join(&name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
}
