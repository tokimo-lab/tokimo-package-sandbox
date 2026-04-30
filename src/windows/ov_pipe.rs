//! Overlapped-mode named-pipe wrapper.
//!
//! Windows synchronous named pipes serialize ReadFile and WriteFile against
//! the same pipe instance: a pending blocking read prevents a concurrent
//! write from completing (even from a different thread or via a duplicated
//! HANDLE). Our session protocol needs the reader thread to wait for
//! incoming frames while the caller thread is writing requests, so the
//! pipe must be opened with `FILE_FLAG_OVERLAPPED` and every I/O must
//! supply an OVERLAPPED + event to stage completion.
//!
//! `OvPipe` exposes blocking `Read` / `Write` semantics built on overlapped
//! ReadFile / WriteFile, with an internal event used to wait for the
//! pending operation. Each `OvPipe` owns its own event, so two `OvPipe`s
//! cloned from the same underlying pipe HANDLE can issue concurrent reads
//! and writes without contending on each other's OVERLAPPED state.

#![cfg(target_os = "windows")]

use std::io::{self, Read, Write};

use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
    ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Threading::{CreateEventW, GetCurrentProcess, INFINITE, WaitForSingleObject};
use windows::core::PCWSTR;

/// Overlapped-mode named pipe handle. Owns the HANDLE and an event used
/// to wait for completions. Cloning duplicates both.
pub struct OvPipe {
    pipe: HANDLE,
    event: HANDLE,
}

unsafe impl Send for OvPipe {}
unsafe impl Sync for OvPipe {}

impl OvPipe {
    /// Wrap a pipe HANDLE that was opened with `FILE_FLAG_OVERLAPPED`.
    pub fn from_handle(pipe: HANDLE) -> io::Result<Self> {
        let event = unsafe {
            CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|_| io::Error::from_raw_os_error(GetLastError().0 as i32))?
        };
        Ok(Self { pipe, event })
    }

    /// Duplicate the pipe HANDLE so the new `OvPipe` can issue independent
    /// overlapped operations on the same pipe instance.
    pub fn try_clone(&self) -> io::Result<Self> {
        let mut dup = HANDLE::default();
        unsafe {
            let cur = GetCurrentProcess();
            DuplicateHandle(cur, self.pipe, cur, &mut dup, 0, false, DUPLICATE_SAME_ACCESS)
                .map_err(|_| io::Error::from_raw_os_error(GetLastError().0 as i32))?;
        }
        Self::from_handle(dup)
    }
}

impl Drop for OvPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.pipe);
            let _ = CloseHandle(self.event);
        }
    }
}

fn run_overlapped<F>(pipe: HANDLE, event: HANDLE, op: F) -> io::Result<u32>
where
    F: FnOnce(&mut OVERLAPPED) -> windows::core::Result<()>,
{
    let mut ov = OVERLAPPED::default();
    ov.hEvent = event;
    let r = op(&mut ov);
    if r.is_err() {
        let last = unsafe { GetLastError() };
        if last != ERROR_IO_PENDING {
            if last == ERROR_BROKEN_PIPE || last == ERROR_HANDLE_EOF || last == ERROR_PIPE_NOT_CONNECTED {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(last.0 as i32));
        }
        let w = unsafe { WaitForSingleObject(event, INFINITE) };
        if w != WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WaitForSingleObject = {:?}", w),
            ));
        }
    }
    let mut transferred: u32 = 0;
    unsafe {
        if GetOverlappedResult(pipe, &ov, &mut transferred, false).is_err() {
            let last = GetLastError();
            if last == ERROR_BROKEN_PIPE || last == ERROR_HANDLE_EOF || last == ERROR_PIPE_NOT_CONNECTED {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(last.0 as i32));
        }
    }
    Ok(transferred)
}

impl Read for OvPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pipe = self.pipe;
        let n = run_overlapped(pipe, self.event, |ov| unsafe {
            ReadFile(pipe, Some(buf), None, Some(ov as *mut _))
        })?;
        Ok(n as usize)
    }
}

impl Write for OvPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let pipe = self.pipe;
        let n = run_overlapped(pipe, self.event, |ov| unsafe {
            WriteFile(pipe, Some(buf), None, Some(ov as *mut _))
        })?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
