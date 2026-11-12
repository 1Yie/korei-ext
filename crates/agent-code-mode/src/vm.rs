use crate::{
    allocator::BoundedAllocator,
    protocol::{self, bounded_json, Operation, ParentFrame, ToolRequest, WorkerFrame},
    types::{check_bytes, HARD_FRAME_BYTES},
    CodeModeError, CodeModeRequest, ConsoleEntry, ConsoleStream, ErrorKind,
};
use rquickjs::{
    promise::PromiseState, Context, Ctx, Exception, Function, Object, Promise, Runtime,
};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::HashSet,
    io::{BufRead, Write},
    rc::Rc,
    time::{Duration, Instant},
};

const BOOTSTRAP: &str = r#"
(function(request, log) {
    "use strict";
    const stringify = JSON.stringify.bind(JSON);
    const parse = JSON.parse.bind(JSON);
    const pending = new Map();
    const set = pending.set.bind(pending);
    const get = pending.get.bind(pending);
    const remove = pending.delete.bind(pending);
    const freeze = Object.freeze;
    const isFinite = Number.isFinite;
    const denyCode = function() { throw new TypeError("Dynamic code is disabled"); };
    for (const constructor of [Function, (async function(){}).constructor,
                                (function*(){}).constructor, (async function*(){}).constructor]) {
        Object.defineProperty(constructor.prototype, "constructor",
            {value:denyCode, writable:false, configurable:false});
    }
    for (const name of ["eval", "Function"]) {
        Object.defineProperty(globalThis, name,
            {value:denyCode, writable:false, configurable:false});
    }
    function encode(value) {
        return stringify(value, (_key, item) => {
            const kind = typeof item;
            if (kind === "undefined" || kind === "function" || kind === "symbol" ||
                kind === "bigint" || (kind === "number" && !isFinite(item))) {
                throw new TypeError("Only finite JSON values may cross the tool boundary");
            }
            return item;
        });
    }
    const PromiseType = Promise;
    function invoke(operation) {
        return new PromiseType((resolve, reject) => {
            const id = request(encode(operation));
            set(id, {resolve, reject});
        });
    }
    const tools = freeze({
        list: ({cursor = null} = {}) => invoke({op:"list", cursor}),
        describe: name => invoke({op:"describe", name}),
        call: (name, args) => invoke({op:"call", name, args})
    });
    const write = stream => (...items) => log(stream, items.map(item =>
        typeof item === "string" ? item : encode(item)).join(" "));
    Object.defineProperty(globalThis, "tools", {value:tools});
    Object.defineProperty(globalThis, "console", {value:freeze({
        log:write("stdout"), info:write("stdout"),
        warn:write("stderr"), error:write("stderr")
    })});
    return {
        encode: value => encode(value === undefined ? null : value),
        settle: text => {
            const message = parse(text);
            const entry = get(message.id);
            if (!entry) throw new Error("Unknown tool result");
            remove(message.id);
            if ("Ok" in message.result) entry.resolve(message.result.Ok);
            else {
                const error = new Error(message.result.Err.message);
                Object.assign(error, message.result.Err);
                entry.reject(error);
            }
        }
    };
})
"#;

#[derive(Default)]
struct State {
    next: u64,
    pending: HashSet<u64>,
    requests: Vec<ToolRequest>,
    console: Vec<ConsoleEntry>,
    console_bytes: usize,
    console_entries: usize,
    fatal: Option<CodeModeError>,
}

fn reject<T>(ctx: &Ctx<'_>, state: &mut State, error: CodeModeError) -> rquickjs::Result<T> {
    let message = error.message.clone();
    state.fatal = Some(error);
    Err(Exception::throw_message(ctx, &message))
}

fn exception_error(ctx: &Ctx<'_>, deadline: Instant, error: rquickjs::Error) -> CodeModeError {
    if Instant::now() >= deadline {
        return CodeModeError::new(ErrorKind::Timeout, "JavaScript deadline exceeded");
    }
    let message = if error.is_exception() {
        let exception = ctx.catch();
        if let Some(object) = exception.as_object() {
            if let Ok(kind) = object.get::<_, String>("kind") {
                if let Ok(kind) = serde_json::from_value::<ErrorKind>(Value::String(kind)) {
                    let mut error = CodeModeError::new(
                        kind,
                        object
                            .get::<_, String>("message")
                            .unwrap_or_else(|_| "tool request failed".into()),
                    );
                    error.actual_bytes = object.get("actual_bytes").ok();
                    error.limit_bytes = object.get("limit_bytes").ok();
                    return error;
                }
            }
            object
                .get::<_, String>("message")
                .unwrap_or_else(|_| "JavaScript exception".into())
        } else {
            exception
                .as_string()
                .and_then(|s| s.to_string().ok())
                .unwrap_or_else(|| "JavaScript exception".into())
        }
    } else {
        error.to_string()
    };
    let kind = if message.contains("out of memory")
        || message.contains("stack overflow")
        || message.contains("call stack size")
        || message.contains("allocation")
    {
        ErrorKind::Limit
    } else {
        ErrorKind::JsException
    };
    CodeModeError::new(kind, message)
}

fn memory_error() -> CodeModeError {
    CodeModeError::new(ErrorKind::Limit, "JavaScript memory limit exceeded")
}

fn execute_vm(
    request: &CodeModeRequest,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Value, CodeModeError> {
    request.validate()?;
    let limits = &request.limits;
    let deadline = Instant::now() + Duration::from_millis(limits.deadline_ms);
    let allocator = BoundedAllocator::new(limits.memory_bytes);
    let memory = allocator.status();
    let init_error = |error: rquickjs::Error| {
        if memory.failed() {
            memory_error()
        } else {
            protocol::protocol(error.to_string())
        }
    };
    let runtime = Runtime::new_with_alloc(allocator).map_err(init_error)?;
    runtime.set_max_stack_size(limits.stack_bytes);
    let interrupted_memory = memory.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupted_memory.failed() || Instant::now() >= deadline
    })));
    let context = Context::full(&runtime).map_err(init_error)?;
    let state = Rc::new(RefCell::new(State::default()));
    context.with(|ctx| {
        let js_error = |ctx: &Ctx<'_>, deadline, error| {
            if memory.failed() {
                memory_error()
            } else {
                exception_error(ctx, deadline, error)
            }
        };
        let mut inner = || -> Result<Value, CodeModeError> {
            let state_request = state.clone();
            let request_limits = limits.clone();
            let request_memory = memory.clone();
            let native_request = Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, text: String| -> rquickjs::Result<u64> {
                    let mut state = state_request.borrow_mut();
                    if request_memory.failed() {
                        return reject(&ctx, &mut state, memory_error());
                    }
                    if let Err(error) = check_bytes(
                        "tool arguments",
                        text.len(),
                        request_limits.max_result_bytes,
                    ) {
                        return reject(&ctx, &mut state, error);
                    }
                    if state.next as usize >= request_limits.max_tool_calls
                        || state.pending.len() >= request_limits.max_pending
                    {
                        return reject(
                            &ctx,
                            &mut state,
                            CodeModeError::new(
                                ErrorKind::Limit,
                                "tool call or pending limit exceeded",
                            ),
                        );
                    }
                    let operation: Operation = match serde_json::from_str(&text) {
                        Ok(operation) => operation,
                        Err(error) => return Err(Exception::throw_type(&ctx, &error.to_string())),
                    };
                    if let Operation::Call { name, .. } | Operation::Describe { name } = &operation
                    {
                        if name.is_empty() || name.len() > 1024 {
                            return Err(Exception::throw_type(
                                &ctx,
                                "tool name must contain 1..=1024 bytes",
                            ));
                        }
                    }
                    state.next += 1;
                    let id = state.next;
                    state.pending.insert(id);
                    state.requests.push(ToolRequest { id, operation });
                    Ok(id)
                },
            )
            .map_err(|e| js_error(&ctx, deadline, e))?;
            let state_console = state.clone();
            let console_limits = limits.clone();
            let native_console = Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, stream: String, text: String| -> rquickjs::Result<()> {
                    let mut state = state_console.borrow_mut();
                    let total = state.console_bytes.saturating_add(text.len());
                    if let Err(error) =
                        check_bytes("console", total, console_limits.max_console_bytes)
                    {
                        return reject(&ctx, &mut state, error);
                    }
                    if state.console_entries >= console_limits.max_console_entries {
                        return reject(
                            &ctx,
                            &mut state,
                            CodeModeError::new(ErrorKind::Limit, "console entry limit exceeded"),
                        );
                    }
                    state.console_bytes = total;
                    state.console_entries += 1;
                    state.console.push(ConsoleEntry {
                        stream: if stream == "stderr" {
                            ConsoleStream::Stderr
                        } else {
                            ConsoleStream::Stdout
                        },
                        text,
                    });
                    Ok(())
                },
            )
            .map_err(|e| js_error(&ctx, deadline, e))?;
            let bootstrap: Function = ctx
                .eval(BOOTSTRAP)
                .map_err(|e| js_error(&ctx, deadline, e))?;
            let functions: Object = bootstrap
                .call((native_request, native_console))
                .map_err(|e| js_error(&ctx, deadline, e))?;
            let encode: Function = functions
                .get("encode")
                .map_err(|e| js_error(&ctx, deadline, e))?;
            let settle: Function = functions
                .get("settle")
                .map_err(|e| js_error(&ctx, deadline, e))?;
            let source = format!("(async function() {{\n{}\n}})()", request.source);
            let promise: Promise = ctx.eval(source).map_err(|e| js_error(&ctx, deadline, e))?;
            loop {
                if memory.failed() {
                    return Err(memory_error());
                }
                if let Some(error) = state.borrow().fatal.clone() {
                    return Err(error);
                }
                if Instant::now() >= deadline {
                    return Err(CodeModeError::new(
                        ErrorKind::Timeout,
                        "JavaScript deadline exceeded",
                    ));
                }
                let entries = std::mem::take(&mut state.borrow_mut().console);
                for entry in entries {
                    protocol::write_frame(
                        output,
                        &WorkerFrame::Console { entry },
                        limits.max_frame_bytes,
                    )?;
                }
                match promise.state() {
                    PromiseState::Resolved => {
                        let value = promise
                            .result::<rquickjs::Value>()
                            .unwrap()
                            .map_err(|e| js_error(&ctx, deadline, e))?;
                        let text: String = encode
                            .call((value,))
                            .map_err(|e| js_error(&ctx, deadline, e))?;
                        check_bytes("output", text.len(), limits.max_output_bytes)?;
                        return serde_json::from_str(&text)
                            .map_err(|e| protocol::protocol(e.to_string()));
                    }
                    PromiseState::Rejected => {
                        let error = promise.result::<rquickjs::Value>().unwrap().unwrap_err();
                        return Err(js_error(&ctx, deadline, error));
                    }
                    PromiseState::Pending => {}
                }
                if ctx.execute_pending_job() {
                    continue;
                }
                let requests = std::mem::take(&mut state.borrow_mut().requests);
                for request in requests {
                    protocol::write_frame(
                        output,
                        &WorkerFrame::Request { request },
                        limits.max_frame_bytes,
                    )?;
                }
                if state.borrow().pending.is_empty() {
                    return Err(CodeModeError::new(
                        ErrorKind::JsException,
                        "execution has an unsettled promise with no pending tool calls",
                    ));
                }
                match protocol::read_frame(input, limits.max_frame_bytes)? {
                    ParentFrame::Result { id, result } => {
                        if !state.borrow_mut().pending.remove(&id) {
                            return Err(protocol::protocol("duplicate or unknown tool result ID"));
                        }
                        if let Ok(value) = &result {
                            bounded_json(value, limits.max_result_bytes, "tool result")?;
                        }
                        let text = serde_json::to_string(&ParentFrame::Result { id, result })
                            .map_err(|e| protocol::protocol(e.to_string()))?;
                        settle
                            .call::<_, ()>((text,))
                            .map_err(|e| js_error(&ctx, deadline, e))?;
                    }
                    ParentFrame::Start { .. } => {
                        return Err(protocol::protocol("duplicate start frame"))
                    }
                }
            }
        };
        let result = inner();
        // Logging before a synchronous exception still belongs to this execution.
        for entry in std::mem::take(&mut state.borrow_mut().console) {
            protocol::write_frame(
                output,
                &WorkerFrame::Console { entry },
                limits.max_frame_bytes,
            )?;
        }
        if memory.failed() {
            Err(memory_error())
        } else if let Some(error) = state.borrow().fatal.clone() {
            Err(error)
        } else {
            result
        }
    })
}

/// Run one execution over stdin/stdout and then exit. The process must be sandboxed by its host.
pub fn worker_main() -> Result<(), CodeModeError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    protocol::write_frame(
        &mut output,
        &WorkerFrame::Ready { version: 1 },
        HARD_FRAME_BYTES,
    )?;
    let ParentFrame::Start {
        version: 1,
        request,
    } = protocol::read_frame(&mut input, HARD_FRAME_BYTES)?
    else {
        return Err(protocol::protocol("expected version 1 start frame"));
    };
    let result = execute_vm(&request, &mut input, &mut output);
    let limit = request.limits.max_frame_bytes.clamp(4096, HARD_FRAME_BYTES);
    let frame = WorkerFrame::Finish { result };
    match protocol::encode(&frame, limit) {
        Ok(bytes) => {
            output
                .write_all(&bytes)
                .map_err(|e| protocol::protocol(e.to_string()))?;
            output
                .flush()
                .map_err(|e| protocol::protocol(e.to_string()))
        }
        Err(error) => protocol::write_frame(
            &mut output,
            &WorkerFrame::Finish { result: Err(error) },
            limit,
        ),
    }
}
