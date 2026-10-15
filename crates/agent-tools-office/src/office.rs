//! `office_*` — office-document tools, thin wrappers over `officecli`.
//!
//! Registered only into the `office` agent-mode registry (see `Engine::new`),
//! not the shared `with_builtins` set — they would just be noise in the
//! programming modes. Each spec runs `officecli <cmd> --json` through the same
//! `ctx.sandbox()` pipeline as `bash` (audit → `sandbox_config` → `run_command`),
//! so the permission gate, audit tier and sandbox policy all apply unchanged.
//!
//! `officecli` speaks OpenXML directly: `get`/`query` read, `set`/`add`/
//! `remove`/`move`/`batch`/`merge`/`import` mutate, `open`/`close`/`save` manage
//! the resident process that keeps a document warm across calls, `view`
//! renders a preview, `validate` checks the OpenXML schema, `help` exposes the
//! element property schema, `load_skill` prints a format-specific ruleset,
//! `raw`/`raw-set` is the L3 escape hatch for edits no L2 verb can express.
//! `office_exec` passes a verbatim argv as the last-resort fallback so every
//! officecli verb is reachable without the `bash` tool. All file paths are
//! `ctx.resolve`d before they reach the CLI, so a document can never escape
//! the workspace.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use serde::Deserialize;

use agent_capabilities::SandboxCtx;
use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, ToolError, ToolResult, ToolSpec};
use agent_tools_shell::sandbox_cfg::sandbox_config;

const MAX_OUTPUT_CHARS: usize = 20 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Shared exec helper
// ---------------------------------------------------------------------------

/// Run `officecli <args…> --json` in the sandbox, returning stdout (folded).
/// stderr / non-zero exit → `ToolError::Failed` carrying officecli's own
/// message so the model can self-correct.
async fn run<C: WorkspaceCtx + SandboxCtx>(
    ctx: Arc<C>,
    argv: Vec<String>,
    timeout: Duration,
) -> Result<ToolResult, ToolError> {
    // Build one shell line so the audit + sandbox pipeline matches `bash`'s.
    // `OFFICECLI_NO_AUTO_RESIDENT=1` is load-bearing: every sandbox backend
    // kills the command's process group when the call returns, so officecli's
    // auto-resident dies holding mutations that were never flushed to disk —
    // `add` reports "Added paragraph …" and the file on disk stays unchanged.
    // Without a resident, each call does a synchronous read-modify-write on
    // the file itself, so a reported success always means on-disk truth.
    let cmd = format!("OFFICECLI_NO_AUTO_RESIDENT=1 {}", shell_join(&argv));
    let verdict = agent_sandbox::audit_command_scoped(&cmd, Some(ctx.root()?));
    let sandbox = ctx.sandbox()?;
    let cfg = sandbox_config(&verdict, ctx.root()?, timeout, &ctx.sandbox_limits());

    let output = sandbox
        .run_command(&cmd, &[], &cfg)
        .await
        .map_err(|e| ToolError::Failed(e.to_string()))?;

    if output.is_timeout {
        return Err(ToolError::Failed(format!(
            "officecli timed out after {}s — the resident may be holding the file open",
            timeout.as_secs()
        )));
    }
    if output.status != 0 {
        let mut msg = format!(
            "officecli failed (exit {}):\n{}",
            output.status, output.stderr
        );
        if !output.stdout.is_empty() {
            msg.push_str("\nstdout: ");
            msg.push_str(&output.stdout);
        }
        // `batch` is atomic by default: items that reported `succeeded` were
        // rolled back together with the failures — the model often misses this
        // and tries to "fix" operations that are already gone.
        if output.stdout.contains("\"atomicRolledBack\": true")
            || output.stdout.contains("\"atomicRolledBack\":true")
        {
            msg.push_str(
                "\nNote: the batch is atomic — every item (including the ones \
                 that reported \"succeeded\") was rolled back; the file is \
                 unchanged. Fix the failing items and re-run the batch.",
            );
        }
        return Err(ToolError::Failed(msg));
    }
    let mut content = output.stdout;
    if !output.stderr.is_empty() {
        content.push_str("\n── stderr ──\n");
        content.push_str(&output.stderr);
    }
    Ok(ToolResult::text(fold(&content)))
}

/// Join argv into one shell line, quoting args that need it (paths with
/// spaces, JSON `props` maps). Single-quote everything non-trivial.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            // An empty token must still be quoted: a bare nothing vanishes and
            // every later positional argument shifts one slot left.
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn fold(s: &str) -> String {
    if s.len() <= MAX_OUTPUT_CHARS {
        return s.to_string();
    }
    let head = MAX_OUTPUT_CHARS * 3 / 10;
    let tail = MAX_OUTPUT_CHARS - head;
    let mut out = String::with_capacity(MAX_OUTPUT_CHARS + 80);
    out.push_str(agent_tools_shell::util::head(s, head));
    out.push_str(&format!(
        "\n… [truncated {} bytes] …\n",
        s.len() - head - tail
    ));
    out.push_str(agent_tools_shell::util::tail(s, tail));
    out
}

/// Resolve a model-supplied file path inside the workspace; `officecli` then
/// gets the absolute workspace path.
fn resolve_file<C: WorkspaceCtx>(ctx: &Arc<C>, file: &str) -> Result<String, ToolError> {
    Ok(ctx.resolve(file)?.display().to_string())
}

fn timeout_of(secs: Option<u64>) -> Duration {
    secs.map(Duration::from_secs)
        .unwrap_or(DEFAULT_TIMEOUT)
        .min(Duration::from_secs(600))
}

// ---------------------------------------------------------------------------
// Arg shapes — one per verb group. `props` carries the --prop key/values.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileArgs {
    /// Path to the .docx/.xlsx/.pptx file (workspace-relative or absolute).
    file: String,
    /// Optional timeout in seconds (default 120, max 600).
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetArgs {
    /// Path to the document file.
    file: String,
    /// Node path inside the document (default `/` — the whole tree root).
    path: Option<String>,
    /// How many levels of children to expand (default 1).
    depth: Option<u32>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct QueryArgs {
    /// Path to the document file.
    file: String,
    /// CSS-like selector to query elements (e.g. `table`, `slide > shape`).
    selector: String,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetArgs {
    /// Path to the document file.
    file: String,
    /// Node path to modify.
    path: String,
    /// Properties to set — key→value map (each becomes `--prop k=v`).
    props: std::collections::BTreeMap<String, serde_json::Value>,
    /// Restrict the set to text matching this literal/regex — `--find`.
    find: Option<String>,
    /// Replacement text — `--replace` (needs `find`; use path `/` for
    /// whole-document find&replace).
    replace: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddArgs {
    /// Path to the document file.
    file: String,
    /// Parent node path the new element is added under.
    parent: String,
    /// Element type to create (e.g. `shape`, `paragraph`, `row`, `slide`).
    /// Omit when cloning via `from`.
    #[serde(rename = "type")]
    elem_type: Option<String>,
    /// Initial properties — key→value map.
    props: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// Insert after this anchor path — `--after` (accepts `find:<text>`).
    after: Option<String>,
    /// Insert before this anchor path — `--before` (accepts `find:<text>`).
    before: Option<String>,
    /// 0-based position inside the parent — `--index`.
    index: Option<i64>,
    /// Clone this existing element instead of creating a blank one — `--from`.
    from: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RemoveArgs {
    /// Path to the document file.
    file: String,
    /// Node path to remove.
    path: String,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MoveArgs {
    /// Path to the document file.
    file: String,
    /// Node path to move.
    path: String,
    /// New parent path (`to`), or position anchor (`after`/`before`).
    to: Option<String>,
    after: Option<String>,
    before: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BatchArgs {
    /// Path to the document file.
    file: String,
    /// JSON array of command objects — each `{"command":"<verb>", ...args}`
    /// (sibling fields, not a CLI string). Runs as one open/save cycle.
    commands: serde_json::Value,
    /// Abort on the first failed command — `--stop-on-error`.
    stop_on_error: Option<bool>,
    /// Bypass document protection — `--force`.
    force: Option<bool>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MergeArgs {
    /// Template document (with `{{key}}` placeholders).
    template: String,
    /// Output document path to write.
    output: String,
    /// JSON object of placeholder→value for the merge.
    data: serde_json::Value,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ImportArgs {
    /// Target .xlsx file.
    file: String,
    /// Parent path inside the workbook to import into.
    parent: String,
    /// CSV/TSV source file to import.
    source: String,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateArgs {
    /// Output file — extension picks the format (.docx/.xlsx/.pptx).
    file: String,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ViewArgs {
    /// Path to the document file.
    file: String,
    /// View mode: `text` (default), `annotated`, `outline`, `stats`,
    /// `issues`, `html`, `svg`, `screenshot`, `pdf`, `forms`.
    mode: Option<String>,
    /// Single page/slide index — `--page` (screenshot, docx html).
    page: Option<u32>,
    /// First page/slide — `--start` (text/svg ranges).
    start: Option<u32>,
    /// Last page/slide — `--end` (text/svg ranges).
    end: Option<u32>,
    /// Not accepted — this tool is read-only. Use `office_exec` for an
    /// output file (screenshot/svg/pdf). Kept so an old call gets a clear
    /// error instead of a silent drop.
    output: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HelpArgs {
    /// Topic path, e.g. `pptx shape`, `docx paragraph`, `xlsx cell`,
    /// `pptx add chart`, `docx set run`. Empty = the full command index.
    topic: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SkillArgs {
    /// Specialized ruleset to print: `word`, `pptx`, `excel`, `pitch-deck`,
    /// `morph-ppt`, `morph-ppt-3d`, `academic-paper`, `financial-model`,
    /// `data-dashboard`. Load ONE per artifact.
    name: String,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RawArgs {
    /// Path to the document file.
    file: String,
    /// Document part, e.g. `slide1.xml` (see `office_help` topic `pptx raw`).
    part: String,
    /// XPath to act on — when present together with `action`/`xml` this runs
    /// `raw-set`; otherwise it runs the read-only `raw` dump.
    xpath: Option<String>,
    /// `raw-set` action: `append`, `prepend`, `insertbefore`, `insertafter`,
    /// `replace`, `remove`, `setattr`.
    action: Option<String>,
    /// XML payload for `raw-set`.
    xml: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExecArgs {
    /// Raw officecli argv (everything after the binary name), e.g.
    /// `["help","pptx","shape"]`, `["dump","deck.pptx","/"]`,
    /// `["mark","deck.pptx","/slide[1]/shape[2]","--prop","find=draft"]`.
    /// `--json` is appended automatically; verbs that don't take it are rare —
    /// if one rejects the flag, report the error instead of falling back to
    /// `bash`.
    args: Vec<String>,
    timeout_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Specs — the whole family registered together for the office registry.
// ---------------------------------------------------------------------------

/// Every `office_*` spec. The engine registers the returned vec into the
/// office registry — keeping them out of the shared builtin set.
pub fn specs<C: WorkspaceCtx + SandboxCtx>() -> Vec<ToolSpec<C>> {
    vec![
        office_create(),
        office_open(),
        office_close(),
        office_save(),
        office_get(),
        office_query(),
        office_set(),
        office_add(),
        office_remove(),
        office_move(),
        office_batch(),
        office_merge(),
        office_import(),
        office_view(),
        office_validate(),
        office_help(),
        office_skill(),
        office_raw(),
        office_exec(),
    ]
}

// -- individual specs -------------------------------------------------------

fn office_create<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_create",
        schema: schema_for::<CreateArgs>(
            "Create a blank Office document. The file extension picks the \
             format: .docx, .xlsx or .pptx.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: CreateArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_create args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                // `officecli create` does not create missing parent dirs —
                // the output-layout contract puts every deliverable in its
                // own `<slug>/` folder, which usually does not exist yet.
                if let Some(parent) = std::path::Path::new(&f).parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        ToolError::Failed(format!("office_create: mkdir {}: {e}", parent.display()))
                    })?;
                }
                run(
                    ctx,
                    vec!["officecli".into(), "create".into(), f, "--json".into()],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_open<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_open",
        schema: schema_for::<FileArgs>(
            "No-op kept for workflow compatibility: resident mode is disabled \
             in this sandbox (each `office_*` call writes the file directly), \
             so there is nothing to open.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        // Starting a real resident would leave a doomed process holding
        // unflushed state — every command's process group is killed when the
        // call returns — and the corpse marks the file "unflushed session",
        // spraying a warning onto every subsequent call. Honest no-op instead.
        exec: Arc::new(|_args, _ctx| {
            async move {
                Ok(ToolResult::text(
                    "Resident mode is disabled in this sandbox — every \
                     `office_*` call reads and writes the file directly, so \
                     nothing needs opening (and `office_save`/`office_close` \
                     are unnecessary).",
                ))
            }
            .boxed()
        }),
    }
}

fn office_close<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_close",
        schema: schema_for::<FileArgs>(
            "Flush a resident document to disk and stop its process. Use \
             `office_save` to flush but keep it open.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: FileArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_close args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec!["officecli".into(), "close".into(), f, "--json".into()],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_save<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_save",
        schema: schema_for::<FileArgs>(
            "Flush in-memory document changes to disk while keeping the \
             resident process warm.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: FileArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_save args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec!["officecli".into(), "save".into(), f, "--json".into()],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_get<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_get",
        schema: schema_for::<GetArgs>(
            "Get a document node by path (default `/` = the document root). \
             Read-only.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: GetArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_get args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec![
                        "officecli".into(),
                        "get".into(),
                        f,
                        a.path.unwrap_or_else(|| "/".into()),
                        "--depth".into(),
                        a.depth.unwrap_or(1).to_string(),
                        "--json".into(),
                    ],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_query<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_query",
        schema: schema_for::<QueryArgs>(
            "Query document elements with a CSS-like selector. Read-only.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: QueryArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_query args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec![
                        "officecli".into(),
                        "query".into(),
                        f,
                        a.selector,
                        "--json".into(),
                    ],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_set<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_set",
        schema: schema_for::<SetArgs>(
            "Modify a document node's properties (`props` becomes `--prop k=v`).",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: SetArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_set args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let mut argv = vec!["officecli".into(), "set".into(), file, a.path.clone()];
                if let Some(f) = a.find {
                    argv.extend(["--find".into(), f]);
                }
                if let Some(r) = a.replace {
                    argv.extend(["--replace".into(), r]);
                }
                push_props(&mut argv, &a.props);
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_add<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_add",
        schema: schema_for::<AddArgs>(
            "Add a new element (shape/paragraph/row/slide…) under a parent path.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: AddArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_add args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let mut argv = vec!["officecli".into(), "add".into(), file, a.parent];
                if let Some(t) = a.elem_type {
                    argv.extend(["--type".into(), t]);
                }
                if let Some(x) = a.after {
                    argv.extend(["--after".into(), x]);
                }
                if let Some(x) = a.before {
                    argv.extend(["--before".into(), x]);
                }
                if let Some(i) = a.index {
                    argv.extend(["--index".into(), i.to_string()]);
                }
                if let Some(f) = a.from {
                    argv.extend(["--from".into(), f]);
                }
                if let Some(p) = a.props {
                    push_props(&mut argv, &p);
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_remove<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_remove",
        schema: schema_for::<RemoveArgs>("Remove an element from the document."),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: RemoveArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_remove args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec![
                        "officecli".into(),
                        "remove".into(),
                        file,
                        a.path,
                        "--json".into(),
                    ],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_move<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_move",
        schema: schema_for::<MoveArgs>(
            "Move an element to a new parent (`to`) or position (`after`/`before`).",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: MoveArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_move args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let mut argv = vec!["officecli".into(), "move".into(), file, a.path];
                if let Some(t) = a.to {
                    argv.extend(["--to".into(), t]);
                }
                if let Some(x) = a.after {
                    argv.extend(["--after".into(), x]);
                }
                if let Some(x) = a.before {
                    argv.extend(["--before".into(), x]);
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_batch<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_batch",
        schema: schema_for::<BatchArgs>(
            "Run many document edits in one pass. `commands` is a JSON array of \
             objects like `{\"command\":\"add\",\"parent\":\"/slide[1]\",\"type\":\"shape\",\"props\":{...}}`.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: BatchArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_batch args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let cmds = serde_json::to_string(&a.commands)
                    .map_err(|e| ToolError::Args(format!("office_batch commands: {e}")))?;
                let mut argv = vec![
                    "officecli".into(),
                    "batch".into(),
                    file,
                    "--commands".into(),
                    cmds,
                ];
                if a.stop_on_error == Some(true) {
                    argv.push("--stop-on-error".into());
                }
                if a.force == Some(true) {
                    argv.push("--force".into());
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_merge<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_merge",
        schema: schema_for::<MergeArgs>(
            "Merge a template (with {{key}} placeholders) with JSON `data` into \
             `output`.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: MergeArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_merge args: {e}")))?;
                let template = resolve_file(&ctx, &a.template)?;
                let output = resolve_file(&ctx, &a.output)?;
                let data = serde_json::to_string(&a.data)
                    .map_err(|e| ToolError::Args(format!("office_merge data: {e}")))?;
                run(
                    ctx,
                    vec![
                        "officecli".into(),
                        "merge".into(),
                        template,
                        output,
                        "--data".into(),
                        data,
                        "--json".into(),
                    ],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_import<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_import",
        schema: schema_for::<ImportArgs>(
            "Import CSV/TSV `source` into an .xlsx sheet at `parent`.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: ImportArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_import args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let source = resolve_file(&ctx, &a.source)?;
                run(
                    ctx,
                    vec![
                        "officecli".into(),
                        "import".into(),
                        file,
                        a.parent,
                        source,
                        "--json".into(),
                    ],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

/// Reject any `office_view` call that would write a file. Kept separate from
/// the exec closure so the rule is testable without a tool context.
fn view_read_only(a: &ViewArgs) -> Result<(), ToolError> {
    if a.output.is_some() {
        return Err(ToolError::Args(
            "office_view is read-only and cannot write `output`. To save a \
             rendered file, use office_exec with an explicit -o argv (gated \
             by approval)."
                .into(),
        ));
    }
    Ok(())
}

fn office_view<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_view",
        schema: schema_for::<ViewArgs>(
            "Render a document in a view mode (e.g. `text`, `markdown`, `grid`) \
             for reading. Read-only.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: ViewArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_view args: {e}")))?;
                // This tool is read-only and auto-runs without approval. `-o`
                // writes a file, and the shared office root means that could
                // overwrite another session's deliverable — so refuse it here.
                // Writing a render is an `office_exec` call, which is gated.
                view_read_only(&a)?;
                let file = resolve_file(&ctx, &a.file)?;
                let mut argv = vec!["officecli".into(), "view".into(), file];
                // `mode` is a required positional in officecli; default to text.
                argv.push(a.mode.unwrap_or_else(|| "text".into()));
                if let Some(p) = a.page {
                    argv.extend(["--page".into(), p.to_string()]);
                }
                if let Some(s) = a.start {
                    argv.extend(["--start".into(), s.to_string()]);
                }
                if let Some(e) = a.end {
                    argv.extend(["--end".into(), e.to_string()]);
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_validate<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_validate",
        schema: schema_for::<FileArgs>(
            "Validate the document against the OpenXML schema. Run before \
             delivery — any schema error must be fixed first. Read-only.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: FileArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_validate args: {e}")))?;
                let f = resolve_file(&ctx, &a.file)?;
                run(
                    ctx,
                    vec!["officecli".into(), "validate".into(), f, "--json".into()],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_help<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_help",
        schema: schema_for::<HelpArgs>(
            "Show officecli's element/property schema for a topic (e.g. \
             `pptx shape`, `docx paragraph`, `xlsx cell`, `pptx add chart`). \
             Use this instead of guessing property names — empty `topic` lists \
             every command and element.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: HelpArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_help args: {e}")))?;
                let mut argv = vec!["officecli".into(), "help".into()];
                if let Some(t) = a.topic {
                    argv.extend(t.split_whitespace().map(|s| s.to_string()));
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

fn office_skill<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_skill",
        schema: schema_for::<SkillArgs>(
            "Print a format-specific officecli ruleset (`word`, `pptx`, \
             `excel`, `pitch-deck`, `morph-ppt`, `academic-paper`, \
             `financial-model`, `data-dashboard`, …) — the layout/typography/QA \
             rules that govern one artifact. Load ONE per document.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: SkillArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_skill args: {e}")))?;
                run(
                    ctx,
                    vec!["officecli".into(), "load_skill".into(), a.name],
                    timeout_of(a.timeout_secs),
                )
                .await
            }
            .boxed()
        }),
    }
}

fn office_raw<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_raw",
        schema: schema_for::<RawArgs>(
            "L3 raw-XML layer. With only `part` it dumps the part's XML \
             (read-only); with `xpath` + `action` + `xml` it runs `raw-set` for \
             edits no L2 verb can express.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: RawArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_raw args: {e}")))?;
                let file = resolve_file(&ctx, &a.file)?;
                let mut argv = vec!["officecli".into()];
                if a.xpath.is_some() || a.action.is_some() || a.xml.is_some() {
                    argv.push("raw-set".into());
                    argv.push(file);
                    argv.push(a.part);
                    if let Some(x) = a.xpath {
                        argv.extend(["--xpath".into(), x]);
                    }
                    if let Some(ac) = a.action {
                        argv.extend(["--action".into(), ac]);
                    }
                    if let Some(x) = a.xml {
                        argv.extend(["--xml".into(), x]);
                    }
                } else {
                    argv.push("raw".into());
                    argv.push(file);
                    argv.push(a.part);
                }
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

/// Refuse an `office_exec` argument that names a file outside the workspace:
/// a `..` path segment, or a leading `/` that is an existing host path.
/// A leading `/` that is not on the host (`/body`, `/slide[1]`) is an
/// officecli document path and is allowed. Symlinks are not resolved here —
/// the sandbox mount policy is the backstop for those.
fn check_exec_arg(arg: &str) -> Result<(), ToolError> {
    let has_parent = std::path::Path::new(arg)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if has_parent {
        return Err(ToolError::PathEscape(arg.to_string()));
    }
    if arg.starts_with('/') && std::path::Path::new(arg).exists() {
        return Err(ToolError::PathEscape(arg.to_string()));
    }
    Ok(())
}

fn office_exec<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "office_exec",
        schema: schema_for::<ExecArgs>(
            "Escape hatch: run officecli with a verbatim argv for verbs no \
             dedicated `office_*` tool covers (e.g. `dump`, `mark`, `watch`, \
             `refresh`, `goto`, `plugins`). Prefer the dedicated tools — they \
             keep the call shape uniform.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: Arc::new(|args, ctx| {
            async move {
                let a: ExecArgs = serde_json::from_value(args)
                    .map_err(|e| ToolError::Args(format!("office_exec args: {e}")))?;
                if a.args.is_empty() {
                    return Err(ToolError::Args(
                        "office_exec needs a non-empty `args` argv".into(),
                    ));
                }
                // Argv is free-form, so a file path can sit in any slot. Refuse
                // the two forms that name a file outside the workspace; in-document
                // paths like `/body` or `/slide[1]` are legitimate and pass.
                for arg in &a.args {
                    check_exec_arg(arg)?;
                }
                let mut argv = vec!["officecli".into()];
                argv.extend(a.args);
                argv.push("--json".into());
                run(ctx, argv, timeout_of(a.timeout_secs)).await
            }
            .boxed()
        }),
    }
}

/// Append `--prop k=v` for each entry of a props map.
fn push_props(
    argv: &mut Vec<String>,
    props: &std::collections::BTreeMap<String, serde_json::Value>,
) {
    for (k, v) in props {
        let val = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        argv.extend(["--prop".into(), format!("{k}={val}")]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Plain tokens pass through unquoted — the common case stays readable.
    #[test]
    fn shell_join_leaves_plain_tokens_bare() {
        assert_eq!(
            shell_join(&argv(&["officecli", "get", "a.docx", "/body", "--json"])),
            "officecli get a.docx /body --json"
        );
    }

    /// Anything with spaces or JSON is single-quoted so the shell sees one word.
    #[test]
    fn shell_join_quotes_spaces_and_json() {
        assert_eq!(
            shell_join(&argv(&["officecli", "set", "my deck.pptx", r#"{"a":1}"#])),
            r#"officecli set 'my deck.pptx' '{"a":1}'"#
        );
    }

    /// An embedded single quote is closed, escaped, and reopened.
    #[test]
    fn shell_join_escapes_single_quotes() {
        assert_eq!(
            shell_join(&argv(&["officecli", "set", "it's.docx"])),
            r"officecli set 'it'\''s.docx'"
        );
    }

    /// An empty argument must survive as an explicit empty word. Dropping it
    /// shifts every following positional argument one slot left.
    #[test]
    fn shell_join_keeps_empty_argument() {
        assert_eq!(
            shell_join(&argv(&["officecli", "set", "f.docx", "", "--json"])),
            "officecli set f.docx '' --json"
        );
    }

    /// Short output is returned untouched.
    #[test]
    fn fold_passes_short_output_through() {
        assert_eq!(fold("hello"), "hello");
    }

    /// Long output keeps its head and tail and names what was dropped.
    #[test]
    fn fold_truncates_middle_and_reports_bytes() {
        let s = "a".repeat(MAX_OUTPUT_CHARS * 2);
        let out = fold(&s);
        assert!(out.len() < s.len());
        assert!(out.contains("[truncated"));
        assert!(out.starts_with('a') && out.ends_with('a'));
    }

    /// `office_view` is read-only: an `output` path would overwrite a file,
    /// so it is refused, while a plain read still goes through.
    #[test]
    fn view_refuses_output_path() {
        let read = ViewArgs {
            file: "a.docx".into(),
            mode: Some("text".into()),
            page: None,
            start: None,
            end: None,
            output: None,
            timeout_secs: None,
        };
        assert!(view_read_only(&read).is_ok());

        let writing = ViewArgs {
            output: Some("victim.txt".into()),
            ..read
        };
        let err = view_read_only(&writing).unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
    }

    /// `office_exec` must refuse a `..` escape and a real host absolute path,
    /// but let an in-document path (`/body`) and ordinary values through.
    #[test]
    fn exec_arg_guard_blocks_escapes_but_keeps_document_paths() {
        assert!(check_exec_arg("/body").is_ok());
        assert!(check_exec_arg("/slide[1]").is_ok());
        assert!(check_exec_arg("text=hello").is_ok());
        assert!(check_exec_arg("deck.pptx").is_ok());
        assert!(check_exec_arg("../secret.docx").is_err());
        assert!(check_exec_arg("assets/../../x").is_err());
        assert!(check_exec_arg("/etc/hostname").is_err());
    }

    /// Missing timeout uses the default; an oversized one is clamped.
    #[test]
    fn timeout_of_defaults_and_clamps() {
        assert_eq!(timeout_of(None), DEFAULT_TIMEOUT);
        assert_eq!(timeout_of(Some(5)), Duration::from_secs(5));
        assert_eq!(timeout_of(Some(10_000)), Duration::from_secs(600));
    }
}
