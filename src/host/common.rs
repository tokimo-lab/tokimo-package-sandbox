//! Shared helpers: process monitoring, rlimit, stdio piping.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::ResourceLimits;
use crate::{Error, Result};

pub(crate) const MEMORY_CHECK_INTERVAL_MS: u64 = 100;
const TIMEOUT_GRACE_SECS: u64 = 2;

pub(crate) fn pipe_stdio(cmd: &mut Command) {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
}

#[cfg(target_os = "linux")]
pub(crate) fn get_process_memory(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(kb) = parts[1].parse::<u64>()
            {
                return Some(kb * 1024);
            }
            break;
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub(crate) fn get_process_memory(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim().parse::<u64>().ok().map(|kb| kb * 1024)
}

fn get_children_peak_rss_bytes() -> Option<u64> {
    use nix::libc::{RUSAGE_CHILDREN, getrusage, rusage};
    let mut usage: rusage = unsafe { std::mem::zeroed() };
    let ret = unsafe { getrusage(RUSAGE_CHILDREN, &mut usage) };
    if ret != 0 {
        return None;
    }
    let maxrss = usage.ru_maxrss;
    if maxrss <= 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(maxrss as u64)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(maxrss as u64 * 1024)
    }
}

/// Wait for a child with timeout + memory cap.
/// Returns (stdout, stderr, exit_code, timed_out, oom_killed).
pub(crate) fn wait_with_timeout(
    child: &mut Child,
    timeout_secs: u64,
    memory_limit_bytes: u64,
    stream_stderr: bool,
) -> Result<(String, String, i32, bool, bool)> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let check_interval = Duration::from_millis(MEMORY_CHECK_INTERVAL_MS);

    // EOF stdin so the child doesn't block on read.
    let _ = child.stdin.take();

    let stdout_handle = child.stdout.take().map(|mut out| {
        thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        })
    });
    let stderr_handle = child.stderr.take().map(|mut err| {
        thread::spawn(move || {
            let mut s = String::new();
            let mut buf = [0u8; 4096];
            loop {
                match err.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if stream_stderr {
                            let _ = std::io::stderr().write_all(&buf[..n]);
                            let _ = std::io::stderr().flush();
                        }
                    }
                    Err(_) => break,
                }
            }
            s
        })
    });

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
                let stderr = stderr_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();

                if let Some(peak) = get_children_peak_rss_bytes()
                    && memory_limit_bytes > 0
                    && peak > memory_limit_bytes
                {
                    return Ok((
                        stdout,
                        format!(
                            "{}\nsandbox: peak RSS {} MB exceeded limit {} MB",
                            stderr,
                            peak / (1024 * 1024),
                            memory_limit_bytes / (1024 * 1024),
                        ),
                        -1,
                        false,
                        true,
                    ));
                }
                return Ok((stdout, stderr, status.code().unwrap_or(-1), false, false));
            }
            Ok(None) => {}
            Err(e) => {
                let _ = stdout_handle.map(|h| h.join());
                let _ = stderr_handle.map(|h| h.join());
                return Err(Error::exec(format!("wait failed: {}", e)));
            }
        }

        if start.elapsed() > timeout {
            kill_progressive(child, stdout_handle, stderr_handle);
            return Ok((
                String::new(),
                format!("sandbox: killed after {}s timeout", timeout_secs),
                -1,
                true,
                false,
            ));
        }

        if memory_limit_bytes > 0
            && let Some(mem) = get_process_memory(child.id())
            && mem > memory_limit_bytes
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.map(|h| h.join());
            let _ = stderr_handle.map(|h| h.join());
            return Ok((
                String::new(),
                format!(
                    "sandbox: killed, memory {} MB > limit {} MB",
                    mem / (1024 * 1024),
                    memory_limit_bytes / (1024 * 1024)
                ),
                -1,
                false,
                true,
            ));
        }
        thread::sleep(check_interval);
    }
}

fn kill_progressive(
    child: &mut Child,
    stdout_handle: Option<thread::JoinHandle<String>>,
    stderr_handle: Option<thread::JoinHandle<String>>,
) {
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(TIMEOUT_GRACE_SECS);
    while Instant::now() < deadline {
        if child.try_wait().ok().and_then(|s| s).is_some() {
            let _ = stdout_handle.map(|h| h.join());
            let _ = stderr_handle.map(|h| h.join());
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_handle.map(|h| h.join());
    let _ = stderr_handle.map(|h| h.join());
}

/// Apply POSIX rlimits. Must be called inside a `pre_exec` closure.
///
/// Note: RLIMIT_NPROC is intentionally NOT applied on Linux because it counts
/// processes of the calling user across the whole system, not within the
/// sandbox. Using it here would make bwrap's own clone() fail whenever the
/// user already has more than `max_processes` processes running.
///
/// # Safety
/// Runs after fork, before exec.
pub(crate) unsafe fn apply_rlimits(limits: &ResourceLimits) {
    unsafe {
        use nix::libc::{RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE, rlimit, setrlimit};
        if limits.has_memory_limit() {
            let mem = rlimit {
                rlim_cur: limits.max_memory_bytes(),
                rlim_max: limits.max_memory_bytes(),
            };
            setrlimit(RLIMIT_AS, &mem);
        }
        let cpu = rlimit {
            rlim_cur: limits.timeout_secs.saturating_add(5),
            rlim_max: limits.timeout_secs.saturating_add(5),
        };
        if limits.has_cpu_time_limit() {
            setrlimit(RLIMIT_CPU, &cpu);
        }
        if limits.has_file_size_limit() {
            let fs = rlimit {
                rlim_cur: limits.max_file_size_mb * 1024 * 1024,
                rlim_max: limits.max_file_size_mb * 1024 * 1024,
            };
            setrlimit(RLIMIT_FSIZE, &fs);
        }
        let _ = limits.max_processes; // reserved for future per-sandbox cgroup use
    }
}

/// Spawn + pipe stdin + wait, returning the assembled result.
pub(crate) fn spawn_run(
    cmd: &mut Command,
    stdin_bytes: Option<&[u8]>,
    limits: &ResourceLimits,
    stream_stderr: bool,
) -> Result<crate::ExecutionResult> {
    let mut child = cmd.spawn().map_err(|e| Error::exec(format!("spawn failed: {}", e)))?;
    wait_with_io(&mut child, stdin_bytes, limits, stream_stderr)
}

/// Wait on an already-spawned child with stdin push and timeout/mem limits.
/// Used by Linux path when pre/post-spawn coordination (e.g. L4 observer
/// finalize) needs to happen BETWEEN `.spawn()` and `.wait()`.
pub(crate) fn wait_with_io(
    child: &mut Child,
    stdin_bytes: Option<&[u8]>,
    limits: &ResourceLimits,
    stream_stderr: bool,
) -> Result<crate::ExecutionResult> {
    wait_with_io_ext(child, stdin_bytes, limits, stream_stderr, None)
}

/// Like `wait_with_io` but when `exit_rx` is Some, the exit status is read
/// from the channel instead of via `Child::wait()`. Used by the seccomp_trace
/// L4 backend whose tracer thread reaps the child via `waitpid(-1, __WALL)`.
pub(crate) fn wait_with_io_ext(
    child: &mut Child,
    stdin_bytes: Option<&[u8]>,
    limits: &ResourceLimits,
    stream_stderr: bool,
    exit_rx: Option<std::sync::mpsc::Receiver<std::process::ExitStatus>>,
) -> Result<crate::ExecutionResult> {
    if let Some(bytes) = stdin_bytes
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(bytes);
    }
    if let Some(rx) = exit_rx {
        return wait_via_channel(child, rx, limits.timeout_secs, stream_stderr);
    }
    let (stdout, stderr, exit_code, timed_out, oom_killed) =
        wait_with_timeout(child, limits.timeout_secs, limits.max_memory_bytes(), stream_stderr)?;
    Ok(crate::ExecutionResult {
        stdout,
        stderr,
        exit_code,
        timed_out,
        oom_killed,
    })
}

fn wait_via_channel(
    child: &mut Child,
    exit_rx: std::sync::mpsc::Receiver<std::process::ExitStatus>,
    timeout_secs: u64,
    stream_stderr: bool,
) -> Result<crate::ExecutionResult> {
    // Drain stdio concurrently. Child::wait() must NOT be called — the
    // tracer thread reaps via waitpid(-1).
    let _ = child.stdin.take();
    let stdout_handle = child.stdout.take().map(|mut out| {
        thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        })
    });
    let stderr_handle = child.stderr.take().map(|mut err| {
        thread::spawn(move || {
            let mut s = String::new();
            let mut buf = [0u8; 4096];
            loop {
                match err.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if stream_stderr {
                            let _ = std::io::stderr().write_all(&buf[..n]);
                            let _ = std::io::stderr().flush();
                        }
                    }
                    Err(_) => break,
                }
            }
            s
        })
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut timed_out = false;
    let status = loop {
        match exit_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(s) => break Some(s),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    // Timeout: kill the child; tracer will see exit and send
                    // status, but we won't wait much longer.
                    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
                    std::thread::sleep(Duration::from_secs(2));
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                    timed_out = true;
                    break exit_rx.recv_timeout(Duration::from_secs(5)).ok();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break None,
        }
    };

    let stdout = stdout_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let stderr = stderr_handle.map(|h| h.join().unwrap_or_default()).unwrap_or_default();

    let exit_code = status.as_ref().and_then(|s| s.code()).unwrap_or(-1);
    Ok(crate::ExecutionResult {
        stdout,
        stderr: if timed_out {
            format!("{}\nsandbox: killed after {}s timeout", stderr, timeout_secs)
        } else {
            stderr
        },
        exit_code,
        timed_out,
        oom_killed: false,
    })
}

/// Locate a tool on PATH (absolute path lookup).
pub(crate) fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}
