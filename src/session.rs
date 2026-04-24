//! Persistent sandbox session: open once, exec many commands sharing state
//! (env, cwd, files, background processes), close when done.
//!
//! ```no_run
//! use tokimo_package_sandbox::{SandboxConfig, Session};
//! let cfg = SandboxConfig::new("/tmp/work");
//! let mut sess = Session::open(&cfg).unwrap();
//! sess.exec("touch hello").unwrap();
//! let out = sess.exec("ls").unwrap();
//! assert!(out.stdout.contains("hello"));
//! sess.exec("export FOO=bar").unwrap();
//! let out = sess.exec("echo $FOO").unwrap();
//! assert_eq!(out.stdout.trim(), "bar");
//! sess.close().unwrap();
//! ```
//!
//! Implementation: a long-running `bash --noprofile --norc` runs inside the
//! sandbox with stdin/stdout/stderr piped. Each `exec()` writes the command
//! followed by sentinel-emitting tail to stdin and waits for the sentinels on
//! stdout (carrying the exit code) and stderr.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::SandboxConfig;
use crate::{Error, Result};

/// Result of a single `Session::exec` call.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Default)]
struct CallSlot {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
    have_stdout: bool,
    have_stderr: bool,
}

#[derive(Default)]
struct SessionState {
    completed: HashMap<u64, CallSlot>,
    closed: bool,
    /// True if either reader thread saw EOF or read error before completion.
    early_eof: bool,
}

pub struct Session {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    state: Arc<(Mutex<SessionState>, Condvar)>,
    sid: String,
    counter: u64,
    readers: Vec<JoinHandle<()>>,
    _keepalive: Box<dyn std::any::Any + Send>,
    timeout: Duration,
}

impl Session {
    /// Open a new persistent session. The sandbox shell is spawned eagerly.
    pub fn open(cfg: &SandboxConfig) -> Result<Self> {
        cfg.validate()?;
        let (mut child, keepalive) = spawn_session_shell(cfg)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::exec("session shell missing stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::exec("session shell missing stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::exec("session shell missing stderr"))?;

        let sid = random_token();
        let state = Arc::new((Mutex::new(SessionState::default()), Condvar::new()));

        let r1 = spawn_reader(stdout, sid.clone(), Stream::Stdout, state.clone());
        let r2 = spawn_reader(stderr, sid.clone(), Stream::Stderr, state.clone());

        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            state,
            sid,
            counter: 0,
            readers: vec![r1, r2],
            _keepalive: keepalive,
            timeout: Duration::from_secs(cfg.limits.timeout_secs.max(1)),
        })
    }

    /// Override the per-`exec` timeout (defaults to `cfg.limits.timeout_secs`).
    pub fn set_exec_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    /// Run `cmd` (a bash snippet) inside the session and return its output.
    /// State (env, cwd, background jobs, files) persists into subsequent calls.
    pub fn exec(&mut self, cmd: &str) -> Result<ExecOutput> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| Error::exec("session is closed"))?;
        self.counter += 1;
        let id = self.counter;

        // Heredoc-wrap user cmd to survive arbitrary content (incl. unbalanced
        // quotes). Random per-call delimiter avoids collisions.
        let delim = format!("__SB_EOF_{}_{}__", self.sid, id);
        let script = format!(
            "eval \"$(cat <<'{delim}'\n{cmd}\n{delim}\n)\"\n__sb_rc=$?\nprintf '\\n__SBOUT_{sid}_{id} %d\\n' \"$__sb_rc\"\nprintf '\\n__SBERR_{sid}_{id}\\n' >&2\n",
            delim = delim,
            cmd = cmd,
            sid = self.sid,
            id = id,
        );
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| Error::exec(format!("write to session stdin: {}", e)))?;
        stdin
            .flush()
            .map_err(|e| Error::exec(format!("flush session stdin: {}", e)))?;

        // Wait for both sentinels.
        let deadline = Instant::now() + self.timeout;
        let (lock, cv) = &*self.state;
        let mut guard = lock
            .lock()
            .map_err(|_| Error::exec("session state poisoned"))?;
        loop {
            if guard.early_eof {
                return Err(Error::exec(
                    "session shell exited unexpectedly (read EOF before sentinels)",
                ));
            }
            if let Some(slot) = guard.completed.get(&id) {
                if slot.have_stdout && slot.have_stderr {
                    let slot = guard.completed.remove(&id).unwrap();
                    return Ok(ExecOutput {
                        stdout: String::from_utf8_lossy(&slot.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&slot.stderr).into_owned(),
                        exit_code: slot.exit_code,
                    });
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::exec(format!(
                    "session exec timed out after {:?}",
                    self.timeout
                )));
            }
            let (g, _) = cv
                .wait_timeout(guard, deadline - now)
                .map_err(|_| Error::exec("session state poisoned"))?;
            guard = g;
        }
    }

    /// Cleanly close the session: send `exit`, close stdin, wait briefly,
    /// then kill if still alive.
    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }

    fn close_inner(&mut self) -> Result<()> {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"exit\n");
            let _ = stdin.flush();
            drop(stdin);
        }
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
        // Reader threads exit on EOF.
        for h in self.readers.drain(..) {
            let _ = h.join();
        }
        if let Ok(mut g) = self.state.0.lock() {
            g.closed = true;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

#[derive(Copy, Clone)]
enum Stream {
    Stdout,
    Stderr,
}

fn spawn_reader<R: Read + Send + 'static>(
    mut r: R,
    sid: String,
    which: Stream,
    state: Arc<(Mutex<SessionState>, Condvar)>,
) -> JoinHandle<()> {
    let pattern = match which {
        Stream::Stdout => format!("\n__SBOUT_{}_", sid),
        Stream::Stderr => format!("\n__SBERR_{}_", sid),
    };
    let pat_bytes = pattern.into_bytes();
    let name = match which {
        Stream::Stdout => "tps-session-stdout",
        Stream::Stderr => "tps-session-stderr",
    };
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut buf: Vec<u8> = Vec::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match r.read(&mut tmp) {
                    Ok(0) => {
                        // EOF before completion → mark early_eof so blocked
                        // exec() unblocks with an error.
                        let (lock, cv) = &*state;
                        if let Ok(mut g) = lock.lock() {
                            g.early_eof = true;
                            cv.notify_all();
                        }
                        break;
                    }
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        // Loop: extract every complete sentinel line.
                        while let Some(pos) = find_subseq(&buf, &pat_bytes) {
                            // Sentinel line spans from pos to next \n.
                            let line_start = pos; // points at '\n'
                            let after = &buf[line_start + 1..];
                            let nl = match after.iter().position(|&b| b == b'\n') {
                                Some(i) => i,
                                None => break, // line not yet complete
                            };
                            let line_end = line_start + 1 + nl + 1; // include trailing \n
                            let body = buf[..line_start].to_vec();
                            let line =
                                std::str::from_utf8(&buf[line_start..line_end]).unwrap_or("");
                            // Parse "<\n>__SBOUT_<sid>_<id> <rc><\n>" or err equivalent.
                            let trimmed = line.trim();
                            // Strip the prefix matching pat_bytes (without leading \n).
                            let prefix = &pat_bytes[1..]; // drop leading \n
                            let prefix_str =
                                std::str::from_utf8(prefix).unwrap_or("");
                            let after_prefix = trimmed.strip_prefix(prefix_str).unwrap_or("");
                            let (id, rc) = parse_sentinel_tail(after_prefix);
                            // Commit to slot.
                            {
                                let (lock, cv) = &*state;
                                if let Ok(mut g) = lock.lock() {
                                    let slot = g.completed.entry(id).or_default();
                                    match which {
                                        Stream::Stdout => {
                                            slot.stdout = body;
                                            slot.exit_code = rc;
                                            slot.have_stdout = true;
                                        }
                                        Stream::Stderr => {
                                            slot.stderr = body;
                                            slot.have_stderr = true;
                                        }
                                    }
                                    cv.notify_all();
                                }
                            }
                            buf.drain(..line_end);
                        }
                    }
                    Err(_) => {
                        let (lock, cv) = &*state;
                        if let Ok(mut g) = lock.lock() {
                            g.early_eof = true;
                            cv.notify_all();
                        }
                        break;
                    }
                }
            }
        })
        .expect("spawn reader thread")
}

fn parse_sentinel_tail(s: &str) -> (u64, i32) {
    // s is like "123 0" (stdout) or "123" (stderr).
    let mut it = s.split_whitespace();
    let id = it.next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0);
    let rc = it.next().and_then(|t| t.parse::<i32>().ok()).unwrap_or(0);
    (id, rc)
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn random_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    format!("{:x}{:x}", nanos, pid)
}

#[cfg(target_os = "linux")]
fn spawn_session_shell(
    cfg: &SandboxConfig,
) -> Result<(Child, Box<dyn std::any::Any + Send>)> {
    crate::linux::spawn_session_shell(cfg)
}

#[cfg(target_os = "macos")]
fn spawn_session_shell(
    cfg: &SandboxConfig,
) -> Result<(Child, Box<dyn std::any::Any + Send>)> {
    crate::macos::spawn_session_shell(cfg)
}

#[cfg(target_os = "windows")]
fn spawn_session_shell(
    cfg: &SandboxConfig,
) -> Result<(Child, Box<dyn std::any::Any + Send>)> {
    crate::windows::spawn_session_shell(cfg)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn spawn_session_shell(
    _cfg: &SandboxConfig,
) -> Result<(Child, Box<dyn std::any::Any + Send>)> {
    Err(Error::validation("Session: unsupported platform"))
}
