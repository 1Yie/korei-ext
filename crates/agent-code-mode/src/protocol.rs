use crate::{types::check_bytes, CodeModeError, CodeModeRequest, ConsoleEntry, ErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    List { cursor: Value },
    Describe { name: String },
    Call { name: String, args: Value },
}

impl Operation {
    pub fn summary(&self) -> (&'static str, Option<String>) {
        match self {
            Self::List { .. } => ("list", None),
            Self::Describe { name } => ("describe", Some(name.clone())),
            Self::Call { name, .. } => ("call", Some(name.clone())),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolRequest {
    pub id: u64,
    pub operation: Operation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ParentFrame {
    Start {
        version: u8,
        request: CodeModeRequest,
    },
    Result {
        id: u64,
        result: Result<Value, CodeModeError>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerFrame {
    Ready {
        version: u8,
    },
    Request {
        request: ToolRequest,
    },
    Console {
        entry: ConsoleEntry,
    },
    Finish {
        result: Result<Value, CodeModeError>,
    },
}

pub(crate) fn bounded_json(
    value: &impl Serialize,
    limit: usize,
    label: &str,
) -> Result<(), CodeModeError> {
    struct ByteCount(usize);
    impl Write for ByteCount {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("JSON byte count overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = ByteCount(0);
    serde_json::to_writer(&mut count, value).map_err(|error| protocol(error.to_string()))?;
    check_bytes(label, count.0, limit)
}

pub(crate) fn protocol(message: impl Into<String>) -> CodeModeError {
    CodeModeError::new(ErrorKind::Protocol, message)
}

pub(crate) fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, CodeModeError> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| protocol(e.to_string()))?;
    check_bytes("frame", bytes.len(), limit)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn write_frame<T: Serialize>(
    output: &mut impl Write,
    value: &T,
    limit: usize,
) -> Result<(), CodeModeError> {
    output
        .write_all(&encode(value, limit)?)
        .map_err(|e| protocol(e.to_string()))?;
    output.flush().map_err(|e| protocol(e.to_string()))
}

pub(crate) async fn write_async<T: Serialize>(
    output: &mut (impl AsyncWrite + Unpin),
    value: &T,
    limit: usize,
) -> Result<(), CodeModeError> {
    output
        .write_all(&encode(value, limit)?)
        .await
        .map_err(|e| protocol(e.to_string()))?;
    output.flush().await.map_err(|e| protocol(e.to_string()))
}

pub(crate) fn read_frame<T: for<'de> Deserialize<'de>>(
    input: &mut impl BufRead,
    limit: usize,
) -> Result<T, CodeModeError> {
    let mut bytes = Vec::new();
    loop {
        let data = input.fill_buf().map_err(|e| protocol(e.to_string()))?;
        if data.is_empty() {
            return Err(protocol("unexpected EOF"));
        }
        let len = data
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(data.len());
        check_bytes(
            "frame",
            bytes.len() + len - usize::from(data[len - 1] == b'\n'),
            limit,
        )?;
        bytes.extend_from_slice(&data[..len]);
        input.consume(len);
        if bytes.last() == Some(&b'\n') {
            return serde_json::from_slice(&bytes).map_err(|e| protocol(e.to_string()));
        }
    }
}

// `bytes` survives cancellation by select!, including a partially read frame.
pub(crate) async fn read_async<T: for<'de> Deserialize<'de>>(
    input: &mut (impl AsyncBufRead + Unpin),
    bytes: &mut Vec<u8>,
    limit: usize,
) -> Result<T, CodeModeError> {
    loop {
        let data = input
            .fill_buf()
            .await
            .map_err(|e| protocol(e.to_string()))?;
        if data.is_empty() {
            return Err(protocol("unexpected EOF"));
        }
        let len = data
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(data.len());
        check_bytes(
            "frame",
            bytes.len() + len - usize::from(data[len - 1] == b'\n'),
            limit,
        )?;
        bytes.extend_from_slice(&data[..len]);
        input.consume(len);
        if bytes.last() == Some(&b'\n') {
            let result = serde_json::from_slice(bytes).map_err(|e| protocol(e.to_string()));
            bytes.clear();
            return result;
        }
    }
}
