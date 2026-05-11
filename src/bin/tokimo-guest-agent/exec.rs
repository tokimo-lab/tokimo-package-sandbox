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
    Spawn {
        argv: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        cwd: Option<String>,
    },
    /// Health-check: reply with `pong`.
    Ping,
    /// Query mount status: check if a path is mounted.
    QueryMount { path: String },
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
    MountStatus { path: String, mounted: bool },
}

/// Handle one RPC request, returning all response frames.
///
/// No vsock or file-system interaction — safe to call in unit tests.
pub async fn handle_request(req: Request) -> Vec<Response> {
    match req {
        Request::Ping => vec![Response::Pong],
        Request::Spawn { argv, env, cwd } => handle_spawn(argv, env, cwd).await,
        Request::QueryMount { path } => vec![handle_query_mount(&path)],
    }
}

async fn handle_spawn(argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>) -> Vec<Response> {
    if argv.is_empty() {
        return vec![Response::Error {
            msg: "empty argv".into(),
        }];
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).envs(env);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    let output = match cmd.output().await {
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

fn handle_query_mount(path: &str) -> Response {
    let mounted = is_path_mounted(path);
    Response::MountStatus {
        path: path.to_owned(),
        mounted,
    }
}

/// Parse /proc/self/mountinfo to check if a path is currently mounted.
///
/// Returns true if the path appears as a mount point (field 5).
/// Ignores octal escape sequences for simplicity (acceptable for /mnt).
fn is_path_mounted(target: &str) -> bool {
    let content = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(c) => c,
        Err(_) => return false,
    };

    for line in content.lines() {
        // Format: 36 35 0:32 / /sys rw,nosuid... - sysfs sysfs rw
        // Field 5 (0-indexed field 4) is the mount point.
        let mut parts = line.split_whitespace();
        if parts.nth(4).map(|p| p == target).unwrap_or(false) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_echo() {
        let req = Request::Spawn {
            argv: vec!["bash".into(), "-c".into(), "echo hi".into()],
            env: vec![],
            cwd: None,
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
            env: vec![],
            cwd: None,
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
            env: vec![],
            cwd: None,
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
