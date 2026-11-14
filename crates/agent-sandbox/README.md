# agent-sandbox

Process confinement and private workspace snapshots for korei hosts.

## Execution Contract

Use `spawn::spawn_isolated` for worker execution and leased tool execution.
The legacy backend entry points reject snapshot requests; the `none` backend
cannot satisfy declared filesystem/network confinement.

The host owns admission, timeouts, cancellation and VM heap limits. Each
execution has an owner thread that retains the actual process, execution scope
and platform cleanup resources. It supervises RSS and process completion
independently of the caller's wait future and Tokio runtime. Startup requires
a Tokio context to register piped I/O.

Keep the `SandboxedChild`, take its `stdin`, `stdout` and `stderr` endpoints,
and consume output alongside protocol activity, tool callbacks and `wait()`.
Call `start_kill()` to request cancellation. `wait()` returning `Ok(status)`
confirms that process cleanup completed and the owned execution scope was
released, including when the target returned a nonzero exit code.
Dropping a wait future stops that waiter; dropping the endpoint requests
cancellation. The owner continues cleanup in both cases. An owner error that
leaves cleanup unproven retains the actual scope and reports an error.

`process::ManagedChild` retains either a native child or that isolated owner
behind the same piped I/O and control operations. `SandboxCtx::spawn_process`
uses `SandboxBackend::spawn_leased` for prepared workspace contexts. Its default
refuses execution. `MacSandboxExec` launches a prepared tool through `spawn_isolated`
with one process and monitored RSS; fork, network and extra read exceptions are rejected.
Other backends still require a Host launcher using the passed lease.
Read-only roots are carried into the process's write-deny policy, and revoked
roots are rejected before launch. Ordinary contexts use the backend's native
wrapper. A shared `Arc<SnapshotLease>` keeps its original root range and blocks
sealing until every context and process owner releases it.

`SandboxCtx::run_command` preserves the backend's ordinary execution path for
unprepared contexts. Prepared contexts use the owned launcher and
`ManagedChild::output`: stdout and stderr share the capture budget declared in
[process.rs](src/process.rs). Timeout and capture failures kill and await the
actual owner before returning. Bash, the test runner and Office use this path.

Persistent Bash services retain the process handle in a session registry.
Prepared contexts require that registry explicitly. Log readers hold the view's
lease through their synchronous file appends; a completed process remains
`draining` until those readers finish. Service stop retains its owner during
cancellation and reports success after process and log cleanup. Registry teardown
requests process cancellation without retaining a context/registry reference cycle.
The Host reads structured service state and private-view association through
`ServiceRegistry::services`; `ServiceRegistry::stop` uses the same confirmed
cleanup path as the service tool.

Background jobs use the same owner and lease-retaining log pump. Their session
registry carries a pause control capability rather than issuing signals from
cached PIDs. Completion notifications follow owner completion and log draining;
unconfirmed cleanup is reported as an error. A prepared job requires its
session's job registry.
`BgRegistry::jobs_for_view` selects jobs by their retained private-view identity
without changing the Host job-event payload.

`ManagedChild::control` retains a pause capability tied to its actual owner.
Native process control is synchronized with reaping. Linux isolated control uses
pinned `cgroup.freeze` and `cgroup.events` descriptors; macOS confirms the single
process's BSD stop state. Cleanup invalidates the capability before releasing
process identity. Windows pause/resume remains unsupported.

Use `WorkerScope::prepare` for a private empty working directory without
workspace authorization. Tool execution requires a live `SnapshotLease` and
the original `SandboxConfig`; its protected paths and read-only mounts are
mapped through that lease. Unsupported policy exceptions fail before launch.
Declarations and enforcement details live in [spawn.rs](src/spawn.rs).

On macOS, select monitored RSS and independently configure the JavaScript VM's
hard heap limit. The execution owner keeps sampling across cancellation,
dropped waiters and caller runtime shutdown.
Sampling permits transient RSS overshoot. Requests for an OS-hard memory
quota are rejected. Linux and Windows use their native memory controls with
the platform-specific metrics documented by `MemoryEnforcement`.

The Windows execution owner retains the native process and Job handles.
AppContainer capabilities and the stdio handle list are attached at suspended
creation; Job assignment completes before resume. Launch failures terminate
and reap the suspended process. Executables and explicit runtime resource
files are copied into a private area; installation and source-workspace ACLs
are untouched. After the main process exits or cancellation is requested,
the owner terminates remaining Job members and waits for `ActiveProcesses`
to reach zero before releasing the scope, AppContainer profile and temporary
ACL grants. See [windows_isolated.rs](src/windows_isolated.rs).
Required Windows runtime environment entries omitted by the caller are obtained
from OS APIs; the host environment is not inherited.

### Linux Execution Setup

Linux hosts provide a trusted delegated cgroup v2 parent through
`IsolatedSpawn::linux_cgroup_parent`. The host must run within the delegated
subtree and have permission to create execution groups and migrate its children.
Migration requires write access to the destination and source/destination
common ancestor's `cgroup.procs`. Each execution group also requires writable
`cgroup.kill` and readable `cgroup.events`. The parent must be a non-threaded
domain cgroup. Other platforms ignore this field.

The owner creates one private group and joins the startup process before its
first external exec. Descendants inherit membership. Normal completion and
cancellation terminate remaining group members and wait for `populated=0`
before reaping the direct child and releasing the scope. Management descriptors
are close-on-exec. Missing delegation, interfaces or permissions reject
execution; the host supplies these conditions without automatic system
configuration. See [linux_cgroup.rs](src/linux_cgroup.rs).

Linux hosts supply the trusted `agent-sandbox-launcher` executable through
`IsolatedSpawn::linux_launcher`. Package this binary as an explicit runtime
file outside source workspaces and private execution directories. It is
mounted read-only at a fixed internal path. The launcher protocol and checks
are defined in [agent-sandbox-launcher.rs](src/bin/agent-sandbox-launcher.rs);
the platform selection and mount wiring are in [spawn.rs](src/spawn.rs).
On other platforms the field must be absent and the launcher binary reports
unsupported execution.

The Linux host must have a non-root real, effective and saved UID. Bubblewrap
initializes its namespaces under the inherited host task allowance; the launcher
then verifies its PID namespace topology, shared UID, cleared capabilities and
`no_new_privs` before lowering both task limits and executing the target directly.
The allowance covers target processes and threads, excluding the verified
single-threaded namespace init. A missing launcher, insufficient inherited
allowance or unsupported topology fails closed.

Dynamic runtime libraries require explicit Host `read_only` grants. Only listed
paths are resolved; dependency discovery and environment-driven grants are
absent. Linux runtime symlinks are resolved one hop at a time through no-follow
directory handles and mounted at their original explicit destinations. Every
hop is checked against source-workspace and private-scope paths and identities;
cycles, excessive chains and metadata errors fail closed.
A protected resource exposed through a conflicting alias
is rejected before launch rather than masking only one visible path.
Snapshot traversal retains its handle-relative, no-follow boundary.

Launcher diagnostics use stderr. A returned process handle is followed by the
supervised wait and worker protocol readiness; initialization failure leaves the
target unexecuted. The host keeps the full endpoint through cancellation and
reap as described above.

## Snapshot Contract

Prepare a `WorkspaceSnapshot` in owner-private storage. Select native cloning
when available or an explicit private full copy; inspect `stats()` for the
actual mode. Preparation budgets cover logical bytes, entries and traversal
depth. They apply to preparation rather than execution-time disk growth.
See [snapshot.rs](src/snapshot.rs).

Stop tool admission and quiesce every writer before sealing. Live leases and
execution owners prevent early sealing. Inspect the sealed diff before
publishing; cancellation before publication leaves source files unchanged.

Files opened through a `SnapshotLease` retain that lease, including controlled
clones. Close every derived file before sealing. `SnapshotFile` provides
controlled I/O, metadata and synchronization without exposing the underlying
file or its OS handle.

Ignore configuration uses the same live workspace authorization for prepared
source paths, private paths and Host aliases. Host configuration outside the
prepared roots is read through pinned directory handles. The immutable
configuration baseline lets callers validate references to Host files; private
configuration changes can select prepared files, but cannot grant access to
new Host targets. See `WorkspaceIo` in `agent-capabilities` for the caller
binding and the FS leased tests for native ignore comparisons.

`append_roots` prepares disjoint roots within the same snapshot and cumulative
preparation budget. Existing `RootId` values and borrowed paths stay valid.
Each lease, including retained file capabilities, keeps the root range granted
when it was minted; a fresh lease sees an entire appended batch. Configuration
reads classify newly prepared source and private paths globally, so old leases
refuse them instead of reading them as Host configuration.

Before appending, the Host must rule out overlap or aliases between the new
sources and every running owner's effective OS read grants, or stop and drain
the affected owners. OS process permissions remain fixed at launch, while the
lease range bounds Rust file operations. The method validates snapshot state,
directory identities, source/storage topology and budget; the Host owns the
process-admission decision.

Publication checks source identities and preimages. Multiple files and
volumes are published incrementally. Consume the complete `PublishReport`,
including applied changes, conflicts, recovery requirements and retained
preimages. Keep recovery paths in the host's durable audit. A failed or partial
publication reports its conflicts. A failure leaves the snapshot sealed when
both applied changes and recovery requirements are empty; partial changes require
recovery and host reconciliation.
Only a complete publication becomes published. Discarding the snapshot only
removes private execution state and preserves host changes and recovery material.

Directory permission changes participate in the sealed diff and source conflict
checks. Publication prepares children before applying final directory permissions
from deepest to shallowest. Retained directory preimages preserve the original
permissions for host reconciliation. Execution-root permission changes are
rejected at seal.

The filesystem boundary uses handle-relative traversal, rejects links and
special files, and preserves native path representations. Windows operations
use directory-rooted NT opens and reject reparse traversal; directory
enumeration, rename, deletion and temporary ACL access use handles. Windows
directory-flush durability remains unverified.
See [snapshot_fs.rs](src/snapshot_fs.rs) and
[snapshot_fs_windows.rs](src/snapshot_fs_windows.rs).

## Verification

Run focused checks from the repository root with the build-resource limits
appropriate for the host:

```sh
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 nice -n 10 cargo test --locked --offline -p agent-sandbox
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 nice -n 10 cargo check --locked --offline -p agent-sandbox --tests --target aarch64-unknown-linux-gnu
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 nice -n 10 cargo check --locked --offline -p agent-sandbox --tests --target x86_64-pc-windows-msvc
```

Execute the tests on each target OS. Cross-target checking verifies compilation.
macOS tests exercise native cloning, workspace and environment denial,
network/fork denial, cancellation/reap, endpoint Drop, caller runtime shutdown,
RSS-limit termination without an active waiter, owner-error lease retention,
and partial-publication recovery. Snapshot regressions cover
zero-applied failures, retained partial preimages, directory permission changes
and concurrent host permission conflicts.

Linux-native acceptance runs the real bwrap startup and enforcement paths:

```sh
export KOREI_TEST_CGROUP_PARENT=/path/to/a/dedicated/delegated/cgroup
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 nice -n 10 cargo test --locked --offline -p agent-sandbox --lib --bin agent-sandbox-launcher --test snapshot_security
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 nice -n 10 cargo test --locked --offline -p agent-sandbox --test isolated_spawn linux_ -- --nocapture
```

Run this entry as an ordinary user on Linux with `bwrap` on `PATH`, unprivileged
user/PID/mount/network namespaces enabled, `/bin/sh`, `/bin/sleep`, readable runtime
libraries, `cc` with pthread support, sufficient inherited host task allowance,
and the cgroup delegation described above. Use a dedicated delegated subtree
for these tests.
The suite covers busy host UID startup, fork/thread allowance boundaries, native
path and argument bytes, missing/invalid resources, capability/topology/limit
rejections, explicit runtime symlinks, protected aliases and cancellation/reap.
Owner regressions cover descendants that keep writing after the main process
exits, double-fork and `setsid()` cancellation, endpoint Drop, setup/exec/migration
failures and retention when cleanup cannot be proven.
Missing prerequisites fail the tests.

The host-UID rejection branch needs a separate run from an existing Linux root
environment, selecting only
`linux_missing_invalid_launcher_and_host_root_are_rejected`. The ordinary-user
run exercises that test's missing and invalid resource branches.

Windows-native unit tests cover AppContainer stdio and cancellation, Job
containment, ADS/hardlink rejection, snapshot publication and in-place
junction mutation with pinned directory handles.
Run them on Windows with
`cargo test --locked --offline -p agent-sandbox --lib --bin agent-sandbox-launcher`
under the same build-resource limits. The
[Code Mode Native workflow](../../.github/workflows/code-mode-native.yml) runs
both platform suites with their native prerequisites.
