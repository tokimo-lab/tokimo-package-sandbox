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
//!
//! On Linux the bash is *not* spawned directly by the host; it runs as a
//! grandchild of `tokimo-sandbox-init` (PID 1 inside the bwrap container) and
//! the host talks to it via the SEQPACKET control socket. Two anonymous
//! pipes inside the host bridge init's `Stdout`/`Stderr` events back into the
//! exact same `Read` impl the sentinel parser already consumes — so the
//! sentinel framing logic is unchanged.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::SandboxConfig;
use crate::{Error, Result};

/// Result of a single `Session::exec` (or `JobHandle::wait`) call.
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
    /// Set true when a backgrounded job (spawn) emits its SBJOB sentinel.
    job_done: bool,
}

#[derive(Default)]
struct SessionState {
    completed: HashMap<u64, CallSlot>,
    closed: bool,
    /// True if either reader thread saw EOF or read error before completion.
    early_eof: bool,
}

/// Factory for opening a PTY inside the same sandbox container as the shell.
/// Stored on `ShellHandle` (and cloned into `Session`) so callers can request
/// additional PTY children any time during the session's lifetime.
///
/// `None` on backends that don't support PTY (currently macOS/Windows).
pub type OpenPtyFn = Box<
    dyn Fn(u16, u16, &[String], &[(String, String)], Option<&str>) -> Result<PtyHandle>
        + Send
        + Sync,
>;

/// Factory for one-shot pipe-mode children. Spawns an independent process
/// inside the same sandbox container (sharing PID namespace, mounts, env)
/// without occupying the long-lived shell. Multiple concurrent calls are
/// safe — each invocation gets its own child with its own `child_id`.
///
/// `None` on backends that don't have an init control socket (macOS/Windows
/// fall back to `Session::exec` if a caller needs one-shot semantics there).
pub type RunOneshotFn = Box<
    dyn Fn(&str, Duration) -> Result<ExecOutput> + Send + Sync,
>;

/// A PTY child running inside the sandbox. Exposes the master fd directly for
/// raw read/write (suitable for terminal_ws bidirectional copy). Resize/kill
/// are routed through the init control socket. Drop kills the child.
pub struct PtyHandle {
    /// Host-side PTY master fd (kernel-allocated). Non-blocking is *not* set
    /// — callers should configure it as appropriate (or read on a thread).
    master: Option<std::os::fd::OwnedFd>,
    /// Stable id of the child as known by the init server.
    child_id: String,
    /// Resize the controlling terminal. `Err` if init connection is dead.
    resize_fn: Box<dyn Fn(u16, u16) -> Result<()> + Send + Sync>,
    /// Best-effort SIGKILL the child (and its pgrp). Idempotent.
    kill_fn: Box<dyn Fn() + Send + Sync>,
    /// Block until the child exits or `deadline` elapses. Returns `Some(rc)`
    /// on exit, `None` on timeout.
    wait_fn: Box<dyn Fn(Duration) -> Option<i32> + Send + Sync>,
    /// Holds the InitClient + any other resources that must outlive the
    /// PtyHandle. Dropped last.
    #[allow(dead_code)]
    keepalive: Box<dyn std::any::Any + Send + Sync>,
}

impl PtyHandle {
    /// Stable child id assigned by the init server.
    pub fn child_id(&self) -> &str {
        &self.child_id
    }

    /// Take ownership of the PTY master fd. After this, read/write/kill on
    /// the host side are the caller's responsibility, but `resize` and the
    /// kept-alive resources still work.
    pub fn take_master(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.master.take()
    }

    /// Borrow the PTY master fd.
    pub fn master_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.master.as_ref().map(|f| f.as_fd())
    }

    /// Resize the controlling terminal.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        (self.resize_fn)(rows, cols)
    }

    /// Best-effort force-kill the child. Idempotent.
    pub fn kill(&self) {
        (self.kill_fn)();
    }

    /// Block until the child exits or `timeout` elapses.
    pub fn wait(&self, timeout: Duration) -> Option<i32> {
        (self.wait_fn)(timeout)
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        master: std::os::fd::OwnedFd,
        child_id: String,
        resize_fn: Box<dyn Fn(u16, u16) -> Result<()> + Send + Sync>,
        kill_fn: Box<dyn Fn() + Send + Sync>,
        wait_fn: Box<dyn Fn(Duration) -> Option<i32> + Send + Sync>,
        keepalive: Box<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        Self {
            master: Some(master),
            child_id,
            resize_fn,
            kill_fn,
            wait_fn,
            keepalive,
        }
    }
}

impl Drop for PtyHandle {
    fn drop(&mut self) {
        // Best-effort kill (so the child doesn't outlive the handle).
        (self.kill_fn)();
    }
}

use std::os::fd::AsFd;

/// Platform-agnostic container around the in-sandbox shell process. The
/// platform-specific `spawn_session_shell` returns one of these — the
/// `Session` itself is identical across platforms.
pub(crate) struct ShellHandle {
    pub stdin: Box<dyn Write + Send>,
    pub stdout: Box<dyn Read + Send>,
    pub stderr: Box<dyn Read + Send>,
    /// Polled by `close_inner`: returns `true` when the shell process has
    /// exited (or transport is dead). `false` means still running.
    pub try_wait: Box<dyn FnMut() -> bool + Send>,
    /// Best-effort force kill the shell. Idempotent.
    pub kill: Box<dyn FnMut() + Send>,
    /// Lifetime guard for any platform-specific resources (Child handle,
    /// spawner thread, InitClient + pump, bwrap PDEATHSIG anchor, …).
    /// Dropping the `ShellHandle` drops this last.
    #[allow(dead_code)]
    pub keepalive: Box<dyn std::any::Any + Send>,
    /// Spawn additional PTY children inside the same sandbox. `None` on
    /// platforms that don't support PTY.
    pub open_pty: Option<Arc<OpenPtyFn>>,
    /// Run a one-shot pipe-mode command without occupying the long-lived
    /// shell. `None` on platforms without an init control socket.
    pub run_oneshot: Option<Arc<RunOneshotFn>>,
}

pub struct Session {
    handle: Option<ShellHandle>,
    stdin: Option<Box<dyn Write + Send>>,
    state: Arc<(Mutex<SessionState>, Condvar)>,
    sid: String,
    counter: u64,
    readers: Vec<JoinHandle<()>>,
    timeout: Duration,
    work_dir: PathBuf,
    open_pty: Option<Arc<OpenPtyFn>>,
    run_oneshot: Option<Arc<RunOneshotFn>>,
}

impl Session {
    /// Open a new persistent session. The sandbox shell is spawned eagerly.
    pub fn open(cfg: &SandboxConfig) -> Result<Self> {
        cfg.validate()?;
        let mut handle = spawn_session_shell(cfg)?;
        let stdin = std::mem::replace(
            &mut handle.stdin,
            Box::new(std::io::sink()) as Box<dyn Write + Send>,
        );
        // Move stdout/stderr Read out so the spawned reader threads can own them.
        let stdout = std::mem::replace(
            &mut handle.stdout,
            Box::new(std::io::empty()) as Box<dyn Read + Send>,
        );
        let stderr = std::mem::replace(
            &mut handle.stderr,
            Box::new(std::io::empty()) as Box<dyn Read + Send>,
        );

        let sid = random_token();
        let state = Arc::new((Mutex::new(SessionState::default()), Condvar::new()));

        let r1 = spawn_reader(stdout, sid.clone(), Stream::Stdout, state.clone());
        let r2 = spawn_reader(stderr, sid.clone(), Stream::Stderr, state.clone());

        let work_dir = cfg
            .work_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.work_dir.clone());

        let open_pty = handle.open_pty.clone();
        let run_oneshot = handle.run_oneshot.clone();

        Ok(Self {
            handle: Some(handle),
            stdin: Some(stdin),
            state,
            sid,
            counter: 0,
            readers: vec![r1, r2],
            timeout: Duration::from_secs(cfg.limits.timeout_secs.max(1)),
            work_dir,
            open_pty,
            run_oneshot,
        })
    }

    /// Run a command as an independent one-shot process inside the same
    /// sandbox container, **without** occupying the long-lived shell.
    ///
    /// Multiple concurrent calls run in parallel: each is a separate child
    /// of the sandbox `init` (PID 1), sharing namespaces / mounts / env but
    /// not the long-lived shell's stdin/stdout. `cwd` and `env` overlay are
    /// **not** persisted across calls — every invocation is a fresh process.
    ///
    /// Use this for read-only / idempotent commands (file reads, glob, grep,
    /// curl, sleep, …) where shell-state persistence isn't needed.
    /// Falls back to `Err(Validation)` on platforms without an init control
    /// socket (macOS/Windows).
    pub fn run_oneshot(&self, cmd: &str, timeout: Duration) -> Result<ExecOutput> {
        let f = self
            .run_oneshot
            .as_ref()
            .ok_or_else(|| Error::validation("Session::run_oneshot unsupported on this platform"))?;
        f(cmd, timeout)
    }

    /// Clone the underlying one-shot factory (if available) so callers can
    /// invoke it concurrently without holding any lock on `Session`.
    ///
    /// Returns `None` on platforms where one-shot execution is unsupported
    /// (currently macOS / Windows).
    #[must_use]
    pub fn run_oneshot_factory(&self) -> Option<Arc<RunOneshotFn>> {
        self.run_oneshot.clone()
    }

    /// Open a PTY child inside the same sandbox container as this session.
    ///
    /// `argv` is the command to run with a controlling terminal (typically
    /// `["/bin/bash", "--login"]` or similar); `env` is appended to the
    /// session's base environment; `cwd` defaults to the sandbox work_dir.
    /// Returns a [`PtyHandle`] exposing the host-side master fd plus
    /// resize/kill/wait controls. The handle's `Drop` kills the child.
    ///
    /// Returns `Err(Validation("Session::open_pty unsupported on this platform"))`
    /// on macOS/Windows.
    pub fn open_pty(
        &self,
        rows: u16,
        cols: u16,
        argv: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<PtyHandle> {
        let f = self
            .open_pty
            .as_ref()
            .ok_or_else(|| Error::validation("Session::open_pty unsupported on this platform"))?;
        f(rows, cols, argv, env, cwd)
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
        tracing::debug!(
            sid = %self.sid,
            exec_id = id,
            cmd_len = cmd.len(),
            timeout_ms = self.timeout.as_millis() as u64,
            "Session::exec ENTER"
        );

        // Heredoc-wrap user cmd to survive arbitrary content (incl. unbalanced
        // quotes). Random per-call delimiter avoids collisions.
        let delim = format!("__SB_EOF_{}_{}__", self.sid, id);
        // KEY TRICK: redirect bash's own stdout/stderr to per-call files for the
        // duration of the eval. Any process backgrounded by the user command
        // (e.g. `foo &`, `nohup ...`, daemons) inherits those file fds at fork
        // time, so AFTER we restore bash's real stdout/stderr, those bg
        // processes keep writing to the (soon-unlinked) files instead of
        // polluting the pipe between bash and our reader thread. This makes
        // exec() framing robust against AI-generated commands that contain
        // arbitrary `&` usage — no parsing required.
        let out_name = format!(".tps_fg_{}_{}.out", self.sid, id);
        let err_name = format!(".tps_fg_{}_{}.err", self.sid, id);
        // KEY: also save bash's real stdin to fd 5 and redirect fd 0 to
        // /dev/null for the duration of the eval. This prevents user commands
        // (e.g. `telnet`, `cat`, `read`) from STEALING bash's stdin pipe — if
        // they did, our next `exec()` would write its script bytes to the
        // hung user process instead of bash, deadlocking the session.
        let script = format!(
            "__o=\"$TMPDIR/{out_name}\"; __e=\"$TMPDIR/{err_name}\"; \
             exec 3>&1 4>&2 5<&0 0</dev/null >\"$__o\" 2>\"$__e\"; \
             eval \"$(cat <<'{delim}'\n{cmd}\n{delim}\n)\"; \
             __sb_rc=$?; \
             exec 0<&5 5<&- >&3 2>&4 3>&- 4>&-; \
             cat \"$__o\"; \
             printf '\\n__SBOUT_{sid}_{id} %d\\n' \"$__sb_rc\"; \
             cat \"$__e\" >&2; \
             printf '\\n__SBERR_{sid}_{id}\\n' >&2; \
             rm -f \"$__o\" \"$__e\"\n",
            delim = delim,
            cmd = cmd,
            sid = self.sid,
            id = id,
            out_name = out_name,
            err_name = err_name,
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
                // On timeout, the user command may have hung bash on a
                // blocking read/syscall. Tear down the session entirely:
                // close stdin (EOF causes bash to exit), then SIGKILL if it
                // doesn't exit within 2s. The sandbox manager will rebuild a
                // fresh session for the next exec.
                let timeout = self.timeout;
                let sid = self.sid.clone();
                let exec_id = id;
                guard.closed = true;
                drop(guard);
                tracing::warn!(
                    sid = %sid,
                    exec_id = exec_id,
                    timeout_ms = timeout.as_millis() as u64,
                    "Session::exec TIMED OUT — tearing down session"
                );
                let _ = self.close_inner();
                return Err(Error::exec(format!(
                    "session exec timed out after {:?}",
                    timeout
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

    /// Spawn `cmd` as a background job inside the session and return a
    /// [`JobHandle`] **immediately**. The next `exec()` (or `spawn()`) is
    /// not blocked by the running job — bash backgrounds it with `&` and
    /// goes back to reading stdin.
    ///
    /// State (env, cwd, files) is fully shared; the job runs in the same
    /// sandboxed bash as everything else. Output is captured to per-job
    /// files in `work_dir` (so concurrent stdout/stderr from many jobs
    /// don't interleave on the wire); call [`JobHandle::wait`] to block on
    /// completion and read them.
    ///
    /// ```no_run
    /// use tokimo_package_sandbox::{SandboxConfig, Session};
    /// let mut sess = Session::open(&SandboxConfig::new("/tmp/work")).unwrap();
    /// let slow = sess.spawn("sleep 2 && echo SLOW").unwrap();
    /// let fast = sess.exec("echo FAST").unwrap();           // returns immediately
    /// assert_eq!(fast.stdout.trim(), "FAST");
    /// let r = slow.wait().unwrap();                          // blocks ~2s
    /// assert_eq!(r.stdout.trim(), "SLOW");
    /// ```
    pub fn spawn(&mut self, cmd: &str) -> Result<JobHandle> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| Error::exec("session is closed"))?;
        self.counter += 1;
        let id = self.counter;

        let delim = format!("__SB_EOF_{}_{}__", self.sid, id);
        let out_name = format!(".tps_job_{}_{}.out", self.sid, id);
        let err_name = format!(".tps_job_{}_{}.err", self.sid, id);
        let pid_name = format!(".tps_job_{}_{}.pid", self.sid, id);

        // Wrap user cmd in `setsid` so the entire job tree lives in its own
        // process group / session. Capture the setsid wrapper's PID into a
        // pidfile so `kill_job` can `kill -KILL -- -<pgid>` that whole tree
        // without touching the session bash.
        //
        // Layout:
        //   { setsid bash -c '<eval USER>' >OUT 2>ERR & echo $! >PIDFILE ;
        //     wait $! ; rc=$? ; printf SBJOB_<sid>_<id> rc ; }
        //
        // The outer brace group is itself backgrounded with `&` so the
        // session bash stays free to accept new commands. `wait $!` makes
        // the brace group's exit reflect the user command's real exit
        // code (instead of `setsid` always exiting 0 after fork).
        let script = format!(
            "{{ setsid bash -c \"$(cat <<'{delim}'\n{cmd}\n{delim}\n)\" > \"$TMPDIR/{out_name}\" 2> \"$TMPDIR/{err_name}\" & __sb_jpid=$! ; printf '%s' \"$__sb_jpid\" > \"$TMPDIR/{pid_name}\" ; wait \"$__sb_jpid\" ; __sb_jrc=$? ; rm -f \"$TMPDIR/{pid_name}\" ; printf '\\n__SBJOB_{sid}_{id} %d\\n' \"$__sb_jrc\" ; }} &\n",
            delim = delim,
            cmd = cmd,
            sid = self.sid,
            id = id,
            out_name = out_name,
            err_name = err_name,
            pid_name = pid_name,
        );
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| Error::exec(format!("write to session stdin: {}", e)))?;
        stdin
            .flush()
            .map_err(|e| Error::exec(format!("flush session stdin: {}", e)))?;

        Ok(JobHandle {
            id,
            sid: self.sid.clone(),
            state: self.state.clone(),
            work_dir: self.work_dir.clone(),
            timeout: self.timeout,
        })
    }

    /// Send `SIGKILL` to a previously-spawned job's entire process group.
    ///
    /// `Session::spawn` puts each job in its own pgroup via `setsid` and
    /// records the leader PID into `$TMPDIR/.tps_job_<sid>_<id>.pid`. This
    /// method writes a one-liner to the session's bash that reads the pid
    /// file and `kill -KILL -- -<pgid>`s the whole tree, then `wait`s for
    /// the brace group sentinel so subsequent `JobHandle::wait` collects
    /// output cleanly.
    ///
    /// The session bash is **not** torn down — the next `exec` / `spawn`
    /// works normally with all session state (env, cwd, files) preserved.
    ///
    /// Returns `Ok(())` if the kill snippet was dispatched. That doesn't
    /// guarantee the job is dead — call `JobHandle::wait_with_timeout`
    /// after this to confirm. If the session itself is closed, returns
    /// `Err`.
    pub fn kill_job(&mut self, job_id: u64) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| Error::exec("session is closed"))?;
        let pid_name = format!(".tps_job_{}_{}.pid", self.sid, job_id);
        // `|| true` so a missing pidfile (race: job already exited) doesn't
        // make bash think the kill failed; we always want to fall through
        // to the brace-group sentinel.
        let snippet = format!(
            "{{ if [ -f \"$TMPDIR/{pid_name}\" ]; then __sb_kpid=$(cat \"$TMPDIR/{pid_name}\" 2>/dev/null) ; if [ -n \"$__sb_kpid\" ]; then kill -KILL -- \"-$__sb_kpid\" 2>/dev/null || true ; fi ; fi ; }}\n",
            pid_name = pid_name,
        );
        stdin
            .write_all(snippet.as_bytes())
            .map_err(|e| Error::exec(format!("write to session stdin: {}", e)))?;
        stdin
            .flush()
            .map_err(|e| Error::exec(format!("flush session stdin: {}", e)))?;
        Ok(())
    }


    fn close_inner(&mut self) -> Result<()> {
        tracing::debug!(
            sid = %self.sid,
            stdin_present = self.stdin.is_some(),
            handle_present = self.handle.is_some(),
            readers = self.readers.len(),
            "Session::close_inner — sending exit to bash"
        );
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"exit\n");
            let _ = stdin.flush();
            drop(stdin); // closes underlying transport stdin (Op::Close on Linux).
        }
        if let Some(mut handle) = self.handle.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if (handle.try_wait)() {
                    break;
                }
                if Instant::now() >= deadline {
                    (handle.kill)();
                    let kill_deadline = Instant::now() + Duration::from_secs(2);
                    while !(handle.try_wait)() && Instant::now() < kill_deadline {
                        thread::sleep(Duration::from_millis(50));
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            // Drop handle (and its keepalive) — releases bwrap PDEATHSIG anchor
            // / Child handle / spawner thread.
            drop(handle);
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

/// A handle to a backgrounded job started via [`Session::spawn`]. Call
/// [`JobHandle::wait`] to block until the job finishes and read its output.
///
/// `JobHandle` is independent of the `Session`'s `&mut` borrow: you can hand
/// it to another thread that calls `wait()` while the original thread keeps
/// issuing `exec()` / `spawn()` on the session. (However, dropping the
/// `Session` kills the bash and therefore the bg job — so keep the session
/// alive until you've collected results.)
pub struct JobHandle {
    id: u64,
    sid: String,
    state: Arc<(Mutex<SessionState>, Condvar)>,
    work_dir: PathBuf,
    timeout: Duration,
}

impl JobHandle {
    /// Numeric id of this job (unique within the originating session).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Block until the job finishes (or the per-exec timeout elapses).
    /// Reads its captured stdout/stderr files from the work directory and
    /// returns them along with the exit code. The temp files are removed.
    pub fn wait(self) -> Result<ExecOutput> {
        self.wait_with_timeout(self.timeout)
    }

    /// Like [`wait`](Self::wait) but with an explicit timeout.
    pub fn wait_with_timeout(&self, timeout: Duration) -> Result<ExecOutput> {
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &*self.state;
        let mut guard = lock
            .lock()
            .map_err(|_| Error::exec("session state poisoned"))?;
        let exit_code = loop {
            if let Some(slot) = guard.completed.get(&self.id) {
                if slot.job_done {
                    let slot = guard.completed.remove(&self.id).unwrap();
                    break slot.exit_code;
                }
            }
            if guard.early_eof {
                return Err(Error::exec(
                    "session shell exited before background job completed",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::exec(format!(
                    "background job {} timed out after {:?}",
                    self.id, timeout
                )));
            }
            let (g, _) = cv
                .wait_timeout(guard, deadline - now)
                .map_err(|_| Error::exec("session state poisoned"))?;
            guard = g;
        };
        drop(guard);

        let out_path = self
            .work_dir
            .join(format!(".tps_job_{}_{}.out", self.sid, self.id));
        let err_path = self
            .work_dir
            .join(format!(".tps_job_{}_{}.err", self.sid, self.id));
        let stdout_bytes = std::fs::read(&out_path).unwrap_or_default();
        let stderr_bytes = std::fs::read(&err_path).unwrap_or_default();
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&err_path);

        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            exit_code,
        })
    }
}

#[derive(Copy, Clone)]
enum Stream {
    Stdout,
    Stderr,
}

fn spawn_reader<R: Read + Send + ?Sized + 'static>(
    r: Box<R>,
    sid: String,
    which: Stream,
    state: Arc<(Mutex<SessionState>, Condvar)>,
) -> JoinHandle<()> {
    // Stdout stream sees TWO sentinel kinds:
    //   - "\n__SBOUT_<sid>_<id> <rc>\n"   (foreground exec result)
    //   - "\n__SBJOB_<sid>_<id> <rc>\n"   (background job completion)
    // Stderr stream sees only:
    //   - "\n__SBERR_<sid>_<id>\n"        (foreground exec stderr terminator)
    let pat_sbout = format!("\n__SBOUT_{}_", sid).into_bytes();
    let pat_sbjob = format!("\n__SBJOB_{}_", sid).into_bytes();
    let pat_sberr = format!("\n__SBERR_{}_", sid).into_bytes();
    let name = match which {
        Stream::Stdout => "tps-session-stdout",
        Stream::Stderr => "tps-session-stderr",
    };
    thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut r = r;
            let mut buf: Vec<u8> = Vec::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match r.read(&mut tmp) {
                    Ok(0) => {
                        let (lock, cv) = &*state;
                        if let Ok(mut g) = lock.lock() {
                            g.early_eof = true;
                            cv.notify_all();
                        }
                        // Loud signal: this is the "bash silently disappeared"
                        // path (signal from outside, OOM, segfault, etc.).
                        // Without this log it's near-impossible to tell apart
                        // from a graceful close.
                        tracing::error!(
                            sid = %sid,
                            stream = name,
                            "session reader hit EOF — bash exited unexpectedly \
                             (look for SIGTERM/SIGKILL/segfault around this time)"
                        );
                        break;
                    }
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        loop {
                            // Find earliest sentinel of any kind on this stream.
                            let (kind, pos) = match which {
                                Stream::Stdout => {
                                    let p_out = find_subseq(&buf, &pat_sbout);
                                    let p_job = find_subseq(&buf, &pat_sbjob);
                                    match (p_out, p_job) {
                                        (Some(a), Some(b)) if a <= b => (SentKind::Out, a),
                                        (Some(_), Some(b)) => (SentKind::Job, b),
                                        (Some(a), None) => (SentKind::Out, a),
                                        (None, Some(b)) => (SentKind::Job, b),
                                        (None, None) => break,
                                    }
                                }
                                Stream::Stderr => match find_subseq(&buf, &pat_sberr) {
                                    Some(a) => (SentKind::Err, a),
                                    None => break,
                                },
                            };
                            // Sentinel line: from `pos` (the leading '\n') to next '\n'.
                            let line_start = pos;
                            let after = &buf[line_start + 1..];
                            let nl = match after.iter().position(|&b| b == b'\n') {
                                Some(i) => i,
                                None => break, // wait for more bytes
                            };
                            let line_end = line_start + 1 + nl + 1;
                            let line = std::str::from_utf8(&buf[line_start..line_end])
                                .unwrap_or("")
                                .trim();
                            let prefix = match kind {
                                SentKind::Out => &pat_sbout[1..],
                                SentKind::Err => &pat_sberr[1..],
                                SentKind::Job => &pat_sbjob[1..],
                            };
                            let prefix_str = std::str::from_utf8(prefix).unwrap_or("");
                            let after_prefix = line.strip_prefix(prefix_str).unwrap_or("");
                            let (id, rc) = parse_sentinel_tail(after_prefix);

                            let (lock, cv) = &*state;
                            if let Ok(mut g) = lock.lock() {
                                let slot = g.completed.entry(id).or_default();
                                match kind {
                                    SentKind::Out => {
                                        // Body bytes before sentinel belong to this exec.
                                        slot.stdout = buf[..line_start].to_vec();
                                        slot.exit_code = rc;
                                        slot.have_stdout = true;
                                    }
                                    SentKind::Err => {
                                        slot.stderr = buf[..line_start].to_vec();
                                        slot.have_stderr = true;
                                    }
                                    SentKind::Job => {
                                        // Background job: its body went to a file,
                                        // NOT to this stream. Don't consume body bytes;
                                        // they belong to a concurrent foreground exec.
                                        slot.exit_code = rc;
                                        slot.job_done = true;
                                    }
                                }
                                cv.notify_all();
                            }

                            // Drain bytes: SBOUT/SBERR consume body too; SBJOB only the line.
                            match kind {
                                SentKind::Out | SentKind::Err => {
                                    buf.drain(..line_end);
                                }
                                SentKind::Job => {
                                    buf.drain(line_start..line_end);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let (lock, cv) = &*state;
                        if let Ok(mut g) = lock.lock() {
                            g.early_eof = true;
                            cv.notify_all();
                        }
                        tracing::error!(
                            sid = %sid,
                            stream = name,
                            error = %e,
                            "session reader I/O error — bash pipe broken"
                        );
                        break;
                    }
                }
            }
        })
        .expect("spawn reader thread")
}

#[derive(Copy, Clone)]
enum SentKind {
    Out,
    Err,
    Job,
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
fn spawn_session_shell(cfg: &SandboxConfig) -> Result<ShellHandle> {
    crate::linux::spawn_session_shell(cfg)
}

#[cfg(target_os = "macos")]
fn spawn_session_shell(cfg: &SandboxConfig) -> Result<ShellHandle> {
    crate::macos::spawn_session_shell(cfg)
}

#[cfg(target_os = "windows")]
fn spawn_session_shell(cfg: &SandboxConfig) -> Result<ShellHandle> {
    crate::windows::spawn_session_shell(cfg)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn spawn_session_shell(_cfg: &SandboxConfig) -> Result<ShellHandle> {
    Err(Error::validation("Session: unsupported platform"))
}

/// Build a `ShellHandle` from a normal `std::process::Child` whose stdio is
/// piped. Used by the macOS and Windows backends.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn shell_handle_from_child(
    mut child: std::process::Child,
    keepalive: Box<dyn std::any::Any + Send>,
) -> Result<ShellHandle> {
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
    let child = Arc::new(Mutex::new(Some(child)));
    let try_wait_child = child.clone();
    let kill_child = child.clone();
    Ok(ShellHandle {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr: Box::new(stderr),
        try_wait: Box::new(move || {
            let mut g = match try_wait_child.lock() {
                Ok(g) => g,
                Err(_) => return true,
            };
            match g.as_mut() {
                None => true,
                Some(c) => matches!(c.try_wait(), Ok(Some(_)) | Err(_)),
            }
        }),
        kill: Box::new(move || {
            if let Ok(mut g) = kill_child.lock() {
                if let Some(c) = g.as_mut() {
                    let _ = c.kill();
                    let _ = c.wait();
                    *g = None;
                }
            }
        }),
        keepalive: Box::new((child, keepalive)),
        open_pty: None,
        run_oneshot: None,
    })
}
