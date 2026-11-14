# agent-tools-serena

Serena semantic code tools run over stdio behind one `serena` meta-tool.
The tool schema and dispatch contract are defined in [tool.rs](src/tool.rs).

## Session Ownership

Install `install_registry(&mut ctx)` for each prepared session. Derived contexts
share that registry. The registry scopes servers by their private project and
linked-root authorization; fresh invocation leases for the same view reuse its
server. Independent private views keep separate servers and indexes.

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
Implementation and regressions are in [manager.rs](src/manager.rs).

Stopping Serena releases its process and stream leases. Invocation contexts,
file handles and other services must also release their leases before the
Host can seal and publish the execution view.

## Verification

Run `cargo test --locked -p agent-tools-serena --lib`. The suite covers status
without startup, repeated stops, cleanup failure retention, view isolation and
new invocation leases. On macOS it also exercises real isolated stdio, explicit
stop, registry Drop and snapshot sealing.
