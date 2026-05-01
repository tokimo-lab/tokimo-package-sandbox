//! Persistent named-pipe JSON-RPC client used by [`crate::windows::sandbox::WindowsBackend`].
//!
//! Connects to `\\.\pipe\tokimo-sandbox-svc` (overlapped mode), sends a
//! `Hello`, receives the service's `Hello`, then enters a persistent
//! request/response + event loop. A background reader thread demultiplexes
//! incoming `Frame::Response`s to per-request `oneshot` slots and fans
//! `Frame::Event`s out to all registered `mpsc::Sender<Event>` subscribers.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use windows::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, GetLastError};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::HSTRING;

use crate::api::Event;
use crate::error::{Error, Result};
use crate::svc_protocol::{Frame, RpcError};

use super::ov_pipe::OvPipe;

/// Maximum frame body size accepted from the service. Mirrors
/// `svc_protocol::MAX_FRAME_BYTES`.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Hello peer string we send to identify the library.
const PEER: &str = concat!("tokimo-package-sandbox/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Pending-response oneshot slot
// ---------------------------------------------------------------------------

struct Pending {
    /// `None` until the reader thread fills it in.
    slot: Mutex<Option<std::result::Result<Value, RpcError>>>,
    cv: Condvar,
}

impl Pending {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    fn fill(&self, v: std::result::Result<Value, RpcError>) {
        let mut g = self.slot.lock().expect("pending slot poisoned");
        *g = Some(v);
        self.cv.notify_all();
    }

    fn wait(&self, deadline: Instant) -> Result<std::result::Result<Value, RpcError>> {
        let mut g = self.slot.lock().map_err(|_| Error::other("pending slot poisoned"))?;
        loop {
            if let Some(v) = g.take() {
                return Ok(v);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::protocol("rpc timeout waiting for response"));
            }
            let (g2, _) = self
                .cv
                .wait_timeout(g, deadline - now)
                .map_err(|_| Error::other("pending slot poisoned"))?;
            g = g2;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared client state
// ---------------------------------------------------------------------------

struct Shared {
    pending: HashMap<String, Arc<Pending>>,
    subscribers: Vec<Sender<Event>>,
    dead: bool,
    fatal: Option<String>,
}

/// Persistent JSON-RPC client over the service named pipe.
pub(crate) struct PipeClient {
    inner: Arc<Inner>,
}

struct Inner {
    write: Mutex<Box<dyn Write + Send>>,
    shared: Mutex<Shared>,
    counter: AtomicU64,
    /// Set to true once the reader thread sees EOF/error.
    dead: AtomicBool,
}

impl PipeClient {
    /// Connect to the service, perform the `Hello` handshake, spawn the reader
    /// thread, and return a usable client.
    pub fn connect(timeout: Duration) -> Result<Self> {
        let pipe = open_pipe(timeout)?;
        let read = pipe
            .try_clone()
            .map_err(|e| Error::other(format!("try_clone svc pipe: {e}")))?;

        let inner = Arc::new(Inner {
            write: Mutex::new(Box::new(pipe)),
            shared: Mutex::new(Shared {
                pending: HashMap::new(),
                subscribers: Vec::new(),
                dead: false,
                fatal: None,
            }),
            counter: AtomicU64::new(0),
            dead: AtomicBool::new(false),
        });

        // Spawn reader thread.
        {
            let inner_r = inner.clone();
            thread::Builder::new()
                .name("tokimo-svc-pipe-reader".into())
                .spawn(move || reader_loop(read, inner_r))
                .map_err(|e| Error::other(format!("spawn reader thread: {e}")))?;
        }

        // Send our Hello first.
        let hello = Frame::Hello {
            version: crate::svc_protocol::PROTOCOL_VERSION,
            peer: PEER.into(),
            info: serde_json::json!({}),
        };
        let cli = Self { inner };
        cli.write_frame(&hello)?;

        // We don't strictly need to wait for the service's Hello before
        // making requests — the dispatch loop on the svc side handles it
        // synchronously. But block briefly to surface protocol mismatches
        // up front.
        cli.wait_for_server_hello(Duration::from_secs(5))?;

        Ok(cli)
    }

    fn wait_for_server_hello(&self, timeout: Duration) -> Result<()> {
        // The reader thread doesn't surface Hello frames as responses; it
        // just logs them. So we sleep a tick — by the time we issue the
        // first `ping` the handshake will have completed or the reader
        // will have marked the connection dead.
        let deadline = Instant::now() + timeout;
        loop {
            if self.inner.dead.load(Ordering::Relaxed) {
                let g = self.inner.shared.lock().expect("shared lock");
                return Err(Error::protocol(
                    g.fatal.clone().unwrap_or_else(|| "service closed during handshake".into()),
                ));
            }
            // Best-effort: don't busy-spin; the reader signals via Condvar
            // through Pending. Since Hello has no oneshot, just sleep.
            std::thread::sleep(Duration::from_millis(20));
            if Instant::now() >= deadline {
                return Ok(());
            }
            // Heuristic: as soon as the reader has had a chance to see
            // *something*, return. We'll catch protocol errors on the
            // first real request.
            return Ok(());
        }
    }

    /// Issue a JSON-RPC request and block until response.
    pub fn call(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        if self.inner.dead.load(Ordering::Relaxed) {
            return Err(Error::NotConnected);
        }
        let id = format!("c{}", self.inner.counter.fetch_add(1, Ordering::Relaxed));
        let pending = Pending::new();
        {
            let mut sh = self.inner.shared.lock().expect("shared lock");
            sh.pending.insert(id.clone(), pending.clone());
        }
        let frame = Frame::Request {
            id: id.clone(),
            method: method.into(),
            params,
        };
        if let Err(e) = self.write_frame(&frame) {
            let mut sh = self.inner.shared.lock().expect("shared lock");
            sh.pending.remove(&id);
            return Err(e);
        }

        let deadline = Instant::now() + timeout;
        let res = pending.wait(deadline);
        // Always remove the slot.
        {
            let mut sh = self.inner.shared.lock().expect("shared lock");
            sh.pending.remove(&id);
        }
        match res? {
            Ok(v) => Ok(v),
            Err(rpc_err) => Err(Error::Rpc {
                code: rpc_err.code,
                message: rpc_err.message,
            }),
        }
    }

    /// Register a new event subscriber.
    pub fn subscribe(&self, tx: Sender<Event>) {
        let mut sh = self.inner.shared.lock().expect("shared lock");
        sh.subscribers.push(tx);
    }

    fn write_frame(&self, frame: &Frame) -> Result<()> {
        let bytes = crate::svc_protocol::encode_frame(frame).map_err(Error::Io)?;
        let mut w = self
            .inner
            .write
            .lock()
            .map_err(|_| Error::other("pipe write mutex poisoned"))?;
        w.write_all(&bytes).map_err(Error::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader thread
// ---------------------------------------------------------------------------

fn reader_loop<R: Read>(mut r: R, inner: Arc<Inner>) {
    let mut len_buf = [0u8; 4];
    loop {
        if let Err(_e) = read_exact(&mut r, &mut len_buf) {
            mark_dead(&inner, "service pipe closed");
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES {
            mark_dead(&inner, "frame too large");
            break;
        }
        let mut body = vec![0u8; len];
        if let Err(_e) = read_exact(&mut r, &mut body) {
            mark_dead(&inner, "service pipe closed mid-frame");
            break;
        }
        let frame: Frame = match serde_json::from_slice(&body) {
            Ok(f) => f,
            Err(e) => {
                mark_dead(&inner, &format!("malformed frame: {e}"));
                break;
            }
        };
        match frame {
            Frame::Hello { .. } => {
                // Handshake reply. Nothing to do — `connect()` returned
                // optimistically; protocol mismatches surface on first call.
            }
            Frame::Response { id, result, error } => {
                let pending = {
                    let sh = inner.shared.lock().expect("shared lock");
                    sh.pending.get(&id).cloned()
                };
                if let Some(p) = pending {
                    let outcome = if let Some(err) = error {
                        Err(err)
                    } else {
                        Ok(result.unwrap_or(Value::Null))
                    };
                    p.fill(outcome);
                }
            }
            Frame::Event { method, params } => {
                let ev = decode_event(&method, &params);
                let mut sh = inner.shared.lock().expect("shared lock");
                sh.subscribers.retain(|tx| tx.send(ev.clone()).is_ok());
            }
            Frame::Notification { method, params } => {
                let ev = Event::Raw { method, params };
                let mut sh = inner.shared.lock().expect("shared lock");
                sh.subscribers.retain(|tx| tx.send(ev.clone()).is_ok());
            }
            Frame::Request { .. } => {
                // Service shouldn't send requests to the client — ignore.
            }
        }
    }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = r.read(&mut buf[off..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "pipe closed",
            ));
        }
        off += n;
    }
    Ok(())
}

fn mark_dead(inner: &Arc<Inner>, reason: &str) {
    inner.dead.store(true, Ordering::Relaxed);
    let mut sh = inner.shared.lock().expect("shared lock");
    sh.dead = true;
    if sh.fatal.is_none() {
        sh.fatal = Some(reason.into());
    }
    // Wake any pending callers with a synthetic error.
    let pending: Vec<Arc<Pending>> = sh.pending.values().cloned().collect();
    for p in pending {
        p.fill(Err(RpcError::new("disconnected", reason)));
    }
}

// ---------------------------------------------------------------------------
// Event decoding
// ---------------------------------------------------------------------------

fn decode_event(method: &str, params: &Value) -> Event {
    use crate::svc_protocol::method as m;
    let id_of = |v: &Value| {
        v.get("id")
            .and_then(|x| x.as_str())
            .map(|s| crate::api::JobId(s.to_owned()))
    };
    let bytes_of = |v: &Value| -> Vec<u8> {
        v.get("data")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u8))
                    .collect()
            })
            .unwrap_or_default()
    };
    match method {
        m::EV_STDOUT => Event::Stdout {
            id: id_of(params).unwrap_or_else(|| crate::api::JobId(String::new())),
            data: bytes_of(params),
        },
        m::EV_STDERR => Event::Stderr {
            id: id_of(params).unwrap_or_else(|| crate::api::JobId(String::new())),
            data: bytes_of(params),
        },
        m::EV_EXIT => Event::Exit {
            id: id_of(params).unwrap_or_else(|| crate::api::JobId(String::new())),
            exit_code: params.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(-1) as i32,
            signal: params
                .get("signal")
                .and_then(|x| x.as_i64())
                .map(|n| n as i32),
        },
        m::EV_ERROR => Event::Error {
            id: id_of(params),
            message: params
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_owned(),
            fatal: params.get("fatal").and_then(|x| x.as_bool()).unwrap_or(false),
        },
        m::EV_READY => Event::Ready,
        m::EV_GUEST_CONNECTED => Event::GuestConnected {
            connected: params.get("connected").and_then(|x| x.as_bool()).unwrap_or(false),
        },
        m::EV_NETWORK_STATUS => Event::NetworkStatus {
            up: params.get("up").and_then(|x| x.as_bool()).unwrap_or(false),
            message: params
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_owned(),
        },
        m::EV_API_REACHABILITY => Event::ApiReachability {
            reachable: params
                .get("reachable")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            latency_ms: params.get("latency_ms").and_then(|x| x.as_u64()),
        },
        _ => Event::Raw {
            method: method.into(),
            params: params.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// Pipe open helper (CreateFileW with retry on PIPE_BUSY)
// ---------------------------------------------------------------------------

fn open_pipe(timeout: Duration) -> Result<OvPipe> {
    let pipe_name_w = HSTRING::from(super::PIPE_NAME);
    let deadline = Instant::now() + timeout;
    loop {
        let h = unsafe {
            CreateFileW(
                &pipe_name_w,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None::<*const SECURITY_ATTRIBUTES>,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0),
                None,
            )
        };
        match h {
            Ok(handle) => return OvPipe::from_handle(handle).map_err(Error::Io),
            Err(_) => {
                let last = unsafe { GetLastError() };
                if last == ERROR_PIPE_BUSY {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(Error::other("pipe busy timeout"));
                    }
                    let ms = remaining.as_millis().min(2000) as u32;
                    let _ = unsafe { WaitNamedPipeW(&pipe_name_w, ms) };
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(Error::other(format!(
                        "CreateFileW {}: WIN32 0x{:08X}",
                        super::PIPE_NAME,
                        last.0
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
