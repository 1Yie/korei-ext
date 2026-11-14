# agent-tools-serena

Serena semantic code tools run over stdio behind one `serena` meta-tool.
The tool schema and dispatch contract are defined in [tool.rs](src/tool.rs).

## Session Ownership

Install `install_registry(&mut ctx)` for each prepared session. Derived contexts
share that registry. The registry scopes servers by their private project and
linked-root authorization; fresh invocation leases for the same view reuse its
server. Independent private views keep separate servers and indexes.

Pure additions to linked-root authorization or the lease root range reuse the
healthy original bridge, key, lease and OS grants. Catalogs and semantic tool
results identify the original coverage and explain that added roots and
permissions require an explicit `serena_stop` followed by a new call.
Revocation, downgrade or replacement waits for the retained owner's cleanup
before a replacement server can start.

Unprepared workspaces use the workspace-root manager. Launch configuration and
transport ownership are defined in [bridge.rs](src/bridge.rs).

## Explicit Control

Call the `serena` tool with:

```json
{"tool":"serena_status"}
```

Status inspection never starts a server. It reports a running server, a stopped
server, or cleanup still pending.

```json
{"tool":"serena_stop"}
```

Stop waits for process termination and stdio cleanup. It is idempotent, reaches
the current private view's retained servers even after authorization changes,
and leaves other views running. A cleanup error retains the registry entry so
the Host can continue to report pending cleanup. A later semantic call starts
a server again.

Host code can use the registry's `status` and `stop` methods directly.
Its `effective_grants` and `effective_grants_for_project` queries expose the
same owner facts recorded before the stdio handshake. Failed startup remains
covered by the execution scope's owner query even when no child was returned.
Invalidation confirms cleanup before releasing a prepared registry entry.
Implementation and regressions are in [manager.rs](src/manager.rs).

Stopping Serena releases its process and stream leases. Invocation contexts,
file handles and other services must also release their leases before the
Host can seal and publish the execution view.

## Verification

Run `cargo test --locked -p agent-tools-serena --lib`. The suite covers status
without startup, repeated stops, cleanup failure retention, view isolation and
new invocation leases. Additive authorization preserves the original coverage;
revocation retains failed cleanup. On macOS the tests also exercise real
isolated stdio across checked root addition, explicit stop, registry Drop and
snapshot sealing.
