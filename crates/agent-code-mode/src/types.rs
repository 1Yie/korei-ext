use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeModeLimits {
    pub max_source_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_result_bytes: usize,
    pub max_output_bytes: usize,
    pub max_console_bytes: usize,
    pub max_console_entries: usize,
    pub max_tool_calls: usize,
    pub max_pending: usize,
    pub max_concurrent: usize,
    pub memory_bytes: usize,
    pub stack_bytes: usize,
    pub deadline_ms: u64,
}

impl Default for CodeModeLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024,
            max_frame_bytes: 256 * 1024,
            max_result_bytes: 64 * 1024,
            max_output_bytes: 64 * 1024,
            max_console_bytes: 32 * 1024,
            max_console_entries: 256,
            max_tool_calls: 64,
            max_pending: 16,
            max_concurrent: 4,
            memory_bytes: 32 * 1024 * 1024,
            stack_bytes: 512 * 1024,
            deadline_ms: 5_000,
        }
    }
}

impl CodeModeLimits {
    pub fn validate(&self) -> Result<(), CodeModeError> {
        for (name, actual, min, max) in [
            ("max_source_bytes", self.max_source_bytes, 1, 1024 * 1024),
            (
                "max_frame_bytes",
                self.max_frame_bytes,
                4096,
                HARD_FRAME_BYTES,
            ),
            ("max_result_bytes", self.max_result_bytes, 1, 1024 * 1024),
            ("max_output_bytes", self.max_output_bytes, 1, 1024 * 1024),
            ("max_console_bytes", self.max_console_bytes, 1, 256 * 1024),
            ("max_console_entries", self.max_console_entries, 1, 4096),
            ("max_tool_calls", self.max_tool_calls, 1, 1024),
            ("max_pending", self.max_pending, 1, 128),
            ("max_concurrent", self.max_concurrent, 1, 32),
            (
                "memory_bytes",
                self.memory_bytes,
                8 * 1024 * 1024,
                256 * 1024 * 1024,
            ),
            ("stack_bytes", self.stack_bytes, 64 * 1024, 16 * 1024 * 1024),
        ] {
            if actual < min || actual > max {
                return Err(CodeModeError::new(
                    ErrorKind::InvalidLimit,
                    format!("{name} must be in {min}..={max}, received {actual}"),
                ));
            }
        }
        if !(1..=30_000).contains(&self.deadline_ms)
            || self.max_concurrent > self.max_pending
            || self.max_pending > self.max_tool_calls
        {
            return Err(CodeModeError::new(
                ErrorKind::InvalidLimit,
                "require deadline_ms in 1..=30000 and concurrent <= pending <= calls",
            ));
        }
        Ok(())
    }
}

pub(crate) const HARD_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeModeRequest {
    pub execution_id: String,
    pub source: String,
    #[serde(default)]
    pub limits: CodeModeLimits,
    /// Host-owned context, withheld from the VM and tool requests.
    #[serde(default)]
    pub metadata: Value,
}

impl CodeModeRequest {
    pub fn validate(&self) -> Result<(), CodeModeError> {
        self.limits.validate()?;
        if self.execution_id.is_empty() || self.execution_id.len() > 128 {
            return Err(CodeModeError::new(
                ErrorKind::Protocol,
                "invalid execution_id",
            ));
        }
        check_bytes("source", self.source.len(), self.limits.max_source_bytes)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidLimit,
    JsException,
    Limit,
    Timeout,
    Cancelled,
    Protocol,
    Tool,
    WorkerCrash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeModeError {
    pub kind: ErrorKind,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub actual_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub limit_bytes: Option<usize>,
}

impl CodeModeError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > 1024 {
            let mut end = 1024;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self {
            kind,
            message,
            actual_bytes: None,
            limit_bytes: None,
        }
    }

    pub(crate) fn bounded(self) -> Self {
        let mut bounded = Self::new(self.kind, self.message);
        bounded.actual_bytes = self.actual_bytes;
        bounded.limit_bytes = self.limit_bytes;
        bounded
    }
}

pub(crate) fn check_bytes(label: &str, actual: usize, limit: usize) -> Result<(), CodeModeError> {
    if actual > limit {
        let mut error = CodeModeError::new(
            ErrorKind::Limit,
            format!("{label} exceeds byte limit: actual={actual}, limit={limit}"),
        );
        error.actual_bytes = Some(actual);
        error.limit_bytes = Some(limit);
        Err(error)
    } else {
        Ok(())
    }
}

pub type ToolError = CodeModeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeOperation {
    List,
    Describe,
    Call,
}

/// Parent-validated correlation, never guest-supplied authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeRequestContext {
    pub(crate) request_id: u64,
    pub(crate) operation: BridgeOperation,
}

impl BridgeRequestContext {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn operation(&self) -> BridgeOperation {
        self.operation
    }
}

/// Controller provenance, independent of any guest-provided error kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerStopCause {
    GuestFinished,
    ParentCancelled,
    DeadlineExceeded,
    ControllerFailed(ErrorKind),
    ExecuteDropped,
}

/// Bounded observations; Stopping precedes bridge Drop, not Host durable drain.
#[derive(Debug)]
pub enum ExecutionEvent<'a> {
    Started,
    RequestAccepted {
        context: BridgeRequestContext,
        name: Option<&'a str>,
    },
    RequestCompleted {
        context: BridgeRequestContext,
        error: Option<ErrorKind>,
        duration_ms: u64,
    },
    Console(&'a ConsoleEntry),
    Stopping(ControllerStopCause),
}

/// Runs synchronously on the controller task. Only update bounded state or notify;
/// blocking I/O and asynchronous persistence belong to the Host's execution owner.
pub trait ExecutionObserver: Send + Sync {
    fn on_event(&self, event: ExecutionEvent<'_>);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleEntry {
    pub stream: ConsoleStream,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSummary {
    pub id: u64,
    pub operation: String,
    pub name: Option<String>,
    pub error: Option<CodeModeError>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeModeResponse {
    pub execution_id: String,
    pub output: Option<Value>,
    pub error: Option<CodeModeError>,
    pub console: Vec<ConsoleEntry>,
    pub calls: Vec<CallSummary>,
    pub duration_ms: u64,
}
