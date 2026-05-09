//! RPC request/response types and pure handler for `tokimo-guest-agent`.
//!
//! `handle_request` is a plain async function with no network dependency —
//! unit tests can call it directly without a vsock socket.

use serde::{Deserialize, Serialize};
use tokio::process::Command;

/// Inbound RPC frame from the host (one per connection).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Spawn a subprocess, collect stdout/stderr, return output + exit code.
    Spawn { argv: Vec<String> },
    /// Health-check: reply with `pong`.
    Ping,
}

/// Outbound RPC frame to the host (one or more per connection).
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
    Error { msg: String },
}

/// Handle one RPC request, returning all response frames.
///
/// No vsock or file-system interaction — safe to call in unit tests.
pub async fn handle_request(req: Request) -> Vec<Response> {
    match req {
        Request::Ping => vec![Response::Pong],
        Request::Spawn { argv } => handle_spawn(argv).await,
    }
}

async fn handle_spawn(argv: Vec<String>) -> Vec<Response> {
    if argv.is_empty() {
        return vec![Response::Error {
            msg: "empty argv".into(),
        }];
    }

    let output = match Command::new(&argv[0]).args(&argv[1..]).output().await {
        Ok(o) => o,
        Err(e) => return vec![Response::Error { msg: e.to_string() }],
    };

    let mut frames = Vec::new();

    if !output.stdout.is_empty() {
        frames.push(Response::Stdout {
            data: String::from_utf8_lossy(&output.stdout).into_owned(),
        });
    }
    if !output.stderr.is_empty() {
        frames.push(Response::Stderr {
            data: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    frames.push(Response::Exit {
        code: output.status.code().unwrap_or(-1),
    });
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_echo() {
        let req = Request::Spawn {
            argv: vec!["bash".into(), "-c".into(), "echo hi".into()],
        };
        let resp = handle_request(req).await;

        assert!(
            resp.iter()
                .any(|r| matches!(r, Response::Stdout { data } if data.contains("hi"))),
            "expected stdout containing 'hi', got: {resp:?}",
        );
        assert!(
            resp.iter().any(|r| matches!(r, Response::Exit { code: 0 })),
            "expected exit code 0, got: {resp:?}",
        );
    }

    #[tokio::test]
    async fn test_spawn_false_exit_code() {
        let req = Request::Spawn {
            argv: vec!["/bin/false".into()],
        };
        let resp = handle_request(req).await;

        assert!(
            resp.iter().any(|r| matches!(r, Response::Exit { code } if *code != 0)),
            "expected non-zero exit, got: {resp:?}",
        );
    }

    #[tokio::test]
    async fn test_spawn_missing_command() {
        let req = Request::Spawn {
            argv: vec!["/nonexistent-tokimo-guest-test".into()],
        };
        let resp = handle_request(req).await;

        assert!(
            resp.iter().any(|r| matches!(r, Response::Error { .. })),
            "expected error for missing command, got: {resp:?}",
        );
    }

    #[tokio::test]
    async fn test_ping() {
        let resp = handle_request(Request::Ping).await;
        assert!(
            matches!(resp.as_slice(), [Response::Pong]),
            "expected [Pong], got: {resp:?}",
        );
    }
}
