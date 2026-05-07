//! Linux CPU affinity helpers shared by the host netstack and the guest
//! pump. Both speak the same protocol over a kernel pipe (or vsock) and
//! benefit from being pinned to fixed, distinct cores so the scheduler
//! can't accidentally co-locate the two hot threads on the same core
//! and serialize them.
//!
//! This module is intentionally tiny — no new deps, just `libc`.
//!
//! Failure modes (cgroup-restricted CPU set, seccomp denial of
//! `sched_setaffinity`, container with effective single-core set) are
//! all *non-fatal*: helpers log to stderr and the caller proceeds.

#![cfg(target_os = "linux")]

use std::mem;

/// List the CPU ids currently allowed for this thread, by reading the
/// effective affinity mask via `sched_getaffinity(0, ...)`. Returns an
/// empty Vec on syscall failure.
pub fn online_cpus() -> Vec<usize> {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        let r = libc::sched_getaffinity(0, mem::size_of::<libc::cpu_set_t>(), &mut set);
        if r != 0 {
            return Vec::new();
        }
        let cap = 8 * mem::size_of::<libc::cpu_set_t>();
        let mut out = Vec::new();
        for cpu in 0..cap {
            if libc::CPU_ISSET(cpu, &set) {
                out.push(cpu);
            }
        }
        out
    }
}

/// Pick `n` distinct CPUs from `available`, preferring even-indexed ones
/// (which are typically distinct physical cores when SMT is on, x86
/// pairs siblings as N / N+CORES, and on AMD/Intel desktop kernels even
/// indices land on different physical cores). `skip` lets a caller avoid
/// CPUs already chosen for another thread group.
///
/// Falls back to any distinct CPUs if not enough even ones are
/// available. Returns an empty Vec only if `available` is empty.
pub fn pick_cpus(available: &[usize], n: usize, skip: &[usize]) -> Vec<usize> {
    if available.is_empty() || n == 0 {
        return Vec::new();
    }
    let is_skipped = |c: &usize| skip.contains(c);

    // Prefer even-indexed cores from the high end (idle-ish on most
    // workstations where low cores host system services and the test
    // harness threads).
    let mut chosen: Vec<usize> = available
        .iter()
        .copied()
        .filter(|c| c % 2 == 0 && !is_skipped(c))
        .rev()
        .take(n)
        .collect();
    if chosen.len() < n {
        for &c in available.iter().rev() {
            if chosen.len() >= n {
                break;
            }
            if !chosen.contains(&c) && !is_skipped(&c) {
                chosen.push(c);
            }
        }
    }
    chosen
}

/// Pin the *current* thread to a single CPU. Logs and returns Err on
/// failure but does not panic — affinity is an optimization, not a
/// correctness requirement.
pub fn pin_current_thread(cpu: usize) -> Result<(), String> {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let r = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
        if r != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("sched_setaffinity(cpu={cpu}): {err}"));
        }
    }
    Ok(())
}
