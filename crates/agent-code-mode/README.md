# agent-code-mode

A QuickJS JavaScript async-body prototype with a one-execution worker process
and a parent-owned asynchronous tool bridge. The host supplies Sandbox launch,
the Kernel gateway, audit, artifacts, and workspace CoW integration. OS
containment requires those integrations and their own end-to-end verification.

## Host Contract

The single `execute` entry point takes ownership of a `ProcessEndpoint` and an
explicit `SchemaBudget` handle. The host creates one budget for its schema
compute capacity and clones that handle into every execution sharing the
capacity. The library creates neither a default budget nor a process launcher.
Tests launch workers directly as VM/process isolation experiments.

The [process contract](src/process.rs) contains the complete `WorkerProcess`
adapter and its piped stdin, stdout, and stderr. A piped Tokio child converts
through `ProcessEndpoint::try_from(child)`. Native Sandbox adapters retain the
entire sandboxed child and its guards, taking only stdio into the endpoint.
They implement supervision and reaping in `wait`, map resource violations to
`CodeModeError`, and initiate termination through `start_kill`. Termination
after exit must be safe against process-identifier reuse.

```rust,no_run
use agent_code_mode::{
    execute, CodeModeLimits, CodeModeRequest, CodeModeResponse, ProcessEndpoint,
    SchemaBudget, ToolBridge,
};
use serde_json::Value;
use std::future::Future;

async fn run_in_host(
    worker: ProcessEndpoint,
    gateway: &dyn ToolBridge,
    schema_budget: &SchemaBudget,
    cancelled: impl Future<Output = ()>,
) -> CodeModeResponse {
    execute(
        worker,
        CodeModeRequest {
            execution_id: "host-issued-id".into(),
            source: r#"
                const page = await tools.list({cursor: null});
                console.log(page);
                return page;
            "#.into(),
            limits: CodeModeLimits::default(),
            metadata: Value::Null,
        },
        gateway,
        schema_budget.clone(),
        cancelled,
    ).await
}
```

`ToolBridge` owns authorization and registry lookup. Its methods return JSON
values or `ToolError`. Bridges may borrow turn-owned policy/hooks: `execute`
accepts `&dyn ToolBridge` and drives scoped futures without spawning bridge
tasks or requiring `'static`. `describe(name)` returns the current registry description:

```json
{
  "name": "registry.original-name",
  "input_schema": {"type": "object"},
  "output_schema": {"type": "object"}
}
```

`input_schema` is required for calls; `output_schema` is optional.
Each call performs a fresh description lookup before argument validation and
dispatch. Input validation and output-schema compilation both precede
`ToolBridge::call`; output values are validated before delivery to JavaScript.
There is no registry or validator cache.

Preparation and validation use `agent_tool::schema`, whose revision is fixed by
the [workspace manifest](../../Cargo.toml). Its bounded offline subset supports
acyclic local JSON Pointer references. External references, recursive/dynamic
references, anchors/resource IDs, regex constraints, content schemas, and
custom vocabularies are unsupported; `format` is an annotation. Literal
annotation values are treated as data. The shared helper owns schema/value
depth, size, expansion, and validation-work budgets.

All schema computations acquire the host's shared budget before entering
Tokio's blocking queue. The blocking closure retains its permit until actual
completion, including after execution cancellation or Drop. An execution
waiting for capacity remains subject to its cancellation and deadline.

The host keeps execution metadata and authorization context. Metadata is
withheld from the worker. Bridge futures must be cancellation-safe and own all
their work: dropping them must stop local work. External effects already
dispatched may have completed. An implementation that spawns detached work
violates this contract.

## JavaScript Contract

The source is an async function body with top-level `return` and `await`:

```javascript
const results = await Promise.allSettled([
  tools.call("registry.original-name", {value: 1}),
  tools.call("registry.original-name", {value: 2})
]);
return results;
```

`tools.list({cursor: null})`, `tools.describe(name)`, and
`tools.call(name, args)` use bounded JSON requests to the parent. A tool failure
rejects its own promise, including its structured `kind`. Console methods
`log`/`info` and `warn`/`error` produce framed stdout/stderr entries.
The VM exports no Node/Deno, filesystem, process, environment, network, or
module-loading host APIs. `eval`, `Function`, and synchronous, async, and
generator function-constructor paths reject dynamic code. Each worker
constructs a new runtime and exits after one execution.

Arguments and returned values cross a finite JSON boundary. Functions, symbols,
BigInts, non-finite numbers, undefined properties, and cycles are rejected.
A body without a returned value yields JSON null.

## Bounds and Completion

[The request types](src/types.rs) own defaults, hard ceilings, and invalid-limit checks for
source, frames, results, output, console bytes/entries, total requests,
pending requests, active bridge futures, memory, stack, and deadline.
The pending limit bounds both queued and active requests. The total request
limit includes list/describe/call; a call's internal schema lookup occupies its
existing concurrency slot.

The [VM allocator](src/allocator.rs) delegates allocation to rquickjs's
`RustAllocator` and accounts for each requested layout, including aligned
payload and allocator header. It enforces `memory_bytes` directly; its sticky
per-VM failure flag identifies OOM even when QuickJS cannot allocate an error
object. Catching OOM cannot recover the execution or dispatch subsequent tools.
VM allocation accounting, native stack bounds, and process RSS are separate:
the host's process adapter supplies OS/RSS supervision.

The [parent controller](src/host.rs) polls one pinned supervision future
alongside startup, framed I/O, schema capacity waits, and callbacks. Successful
process exit can precede a buffered Finish frame; stdout is drained under the
execution deadline. Cancellation or failure kills/reaps the child and drops
bridge futures.

Each execution tracks its schema tasks. Completion and cancellation abort
queued computations and await already-running bounded computations; that
cleanup can finish after the caller's execution deadline. Running blocking
work cannot be forcibly stopped. Dropping `execute` schedules child reaping
and schema-task draining on the current Tokio runtime, retaining compute
permits until their tasks really end. Keep that runtime alive for cleanup.

On completion, same-turn unawaited requests are discarded before dispatch.
Outstanding dispatched work is cancelled, with completed call summaries
preserved. An unsettled promise with no pending bridge request reports an
exception immediately. There are no worker timers or detached worker tasks.

`CodeModeResponse` contains output or a structured error, console entries, call
summaries, and duration. Byte overflow reports actual/limit byte counts; for
an incoming frame, actual is the observed size when reading stops.
Call summaries cover protocol list/describe/call requests, including preparation
failures, and retain identifiers, errors, and durations rather than raw tool
results. The host gateway owns actual-dispatch audit counters.

## Verification

Run from the repository root:

```sh
nice -n 10 cargo test --locked -p agent-code-mode
nice -n 10 cargo check --locked -p agent-code-mode
cargo fmt --check -p agent-code-mode
nice -n 10 cargo clippy --locked -p agent-code-mode --all-targets -- -D warnings
```

The tests use mock bridges and exercise real child processes, bounded
parallelism, independent failures, resource exhaustion, cancellation/reaping,
malformed protocols, and VM isolation. Controlled blocking work verifies shared
budget ownership across cancellation, Drop, queued abort, and subsequent
executions. Fake process adapters verify supervision during worker I/O and
pending callbacks. Allocator tests cover layout accounting, overflow,
reallocation failure, and teardown. The tests use neither a live MCP server
nor JavaScript access to the workspace.

Cross-target checks need the target Rust standard library and a compatible C
compiler/SDK for QuickJS. Native Windows/Linux execution and Sandbox containment
need their own integration verification.

Dependency versions/features and the crate license are in `Cargo.toml`.
