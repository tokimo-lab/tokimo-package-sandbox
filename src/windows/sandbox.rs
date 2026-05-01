//! Windows backend implementation of [`SandboxBackend`].
//!
//! Forwards each public API method as a JSON-RPC request to
//! `tokimo-sandbox-svc.exe` over the persistent named pipe.

#![cfg(target_os = "windows")]

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use serde_json::{Value, json};

use crate::api::{ConfigureParams, Event, JobId, Plan9Share, ShellOpts};
use crate::backend::SandboxBackend;
use crate::error::{Error, Result};
use crate::svc_protocol::{
    AddPlan9ShareParams, BoolValue, CreateDiskImageParams, IdParams, JobIdListResult, JobIdResult, RemovePlan9ShareParams,
    ResizeShellParams, SignalShellParams, SpawnShellParams, WriteStdinParams, method,
};

use super::client::PipeClient;

/// Default RPC call timeout for short calls (configure, status, kill, …).
const SHORT_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Long-running RPC timeout for VM lifecycle and exec.
const LONG_CALL_TIMEOUT: Duration = Duration::from_secs(300);
/// Even-longer timeout for `start_vm` (boots a Linux kernel).
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
/// Connect timeout when first reaching the service.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WindowsBackend {
    client: Arc<PipeClient>,
}

impl WindowsBackend {
    pub fn connect() -> Result<Self> {
        let client = PipeClient::connect(CONNECT_TIMEOUT)?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.client.call(method, params, timeout)
    }
}

impl SandboxBackend for WindowsBackend {
    fn configure(&self, params: ConfigureParams) -> Result<()> {
        let v = serde_json::to_value(&params)?;
        self.call(method::CONFIGURE, v, SHORT_CALL_TIMEOUT)?;
        Ok(())
    }

    fn create_vm(&self) -> Result<()> {
        self.call(method::CREATE_VM, json!({}), LONG_CALL_TIMEOUT)?;
        Ok(())
    }

    fn start_vm(&self) -> Result<()> {
        self.call(method::START_VM, json!({}), BOOT_TIMEOUT)?;
        Ok(())
    }

    fn stop_vm(&self) -> Result<()> {
        self.call(method::STOP_VM, json!({}), LONG_CALL_TIMEOUT)?;
        Ok(())
    }

    fn is_running(&self) -> Result<bool> {
        let v = self.call(method::IS_RUNNING, json!({}), SHORT_CALL_TIMEOUT)?;
        let b: BoolValue = serde_json::from_value(v)?;
        Ok(b.value)
    }

    fn is_guest_connected(&self) -> Result<bool> {
        let v = self.call(method::IS_GUEST_CONNECTED, json!({}), SHORT_CALL_TIMEOUT)?;
        let b: BoolValue = serde_json::from_value(v)?;
        Ok(b.value)
    }

    fn is_process_running(&self, id: &JobId) -> Result<bool> {
        let p = IdParams { id: id.0.clone() };
        let v = self.call(
            method::IS_PROCESS_RUNNING,
            serde_json::to_value(&p)?,
            SHORT_CALL_TIMEOUT,
        )?;
        let b: BoolValue = serde_json::from_value(v)?;
        Ok(b.value)
    }

    fn shell_id(&self) -> Result<JobId> {
        let v = self.call(method::SHELL_ID, json!({}), SHORT_CALL_TIMEOUT)?;
        let r: JobIdResult = serde_json::from_value(v)?;
        Ok(JobId(r.id))
    }

    fn spawn_shell(&self, opts: ShellOpts) -> Result<JobId> {
        let p = SpawnShellParams {
            pty_rows: opts.pty.map(|(r, _)| r),
            pty_cols: opts.pty.map(|(_, c)| c),
            argv: opts.argv,
            env: opts.env,
            cwd: opts.cwd,
        };
        let v = self.call(method::SPAWN_SHELL, serde_json::to_value(&p)?, SHORT_CALL_TIMEOUT)?;
        let r: JobIdResult = serde_json::from_value(v)?;
        Ok(JobId(r.id))
    }

    fn close_shell(&self, id: &JobId) -> Result<()> {
        let p = IdParams { id: id.0.clone() };
        self.call(method::CLOSE_SHELL, serde_json::to_value(&p)?, SHORT_CALL_TIMEOUT)?;
        Ok(())
    }

    fn list_shells(&self) -> Result<Vec<JobId>> {
        let v = self.call(method::LIST_SHELLS, json!({}), SHORT_CALL_TIMEOUT)?;
        let r: JobIdListResult = serde_json::from_value(v)?;
        Ok(r.ids.into_iter().map(JobId).collect())
    }

    fn write_stdin(&self, id: &JobId, data: &[u8]) -> Result<()> {
        let p = WriteStdinParams {
            id: id.0.clone(),
            data: data.to_vec(),
        };
        self.call(method::WRITE_STDIN, serde_json::to_value(&p)?, SHORT_CALL_TIMEOUT)?;
        Ok(())
    }

    fn signal_shell(&self, id: &JobId, sig: i32) -> Result<()> {
        let p = SignalShellParams { id: id.0.clone(), sig };
        self.call(method::SIGNAL_SHELL, serde_json::to_value(&p)?, SHORT_CALL_TIMEOUT)?;
        Ok(())
    }

    fn resize_shell(&self, id: &JobId, rows: u16, cols: u16) -> Result<()> {
        let p = ResizeShellParams {
            id: id.0.clone(),
            rows,
            cols,
        };
        self.call(method::RESIZE_SHELL, serde_json::to_value(&p)?, SHORT_CALL_TIMEOUT)?;
        Ok(())
    }

    fn subscribe(&self) -> Result<Receiver<Event>> {
        let (tx, rx): (Sender<Event>, Receiver<Event>) = channel();
        self.client.subscribe(tx);
        // Inform the service we're listening; ignore errors (best-effort
        // notification — events are delivered regardless).
        let _ = self.call(method::SUBSCRIBE, json!({}), SHORT_CALL_TIMEOUT);
        Ok(rx)
    }

    fn create_disk_image(&self, path: &Path, gib: u64) -> Result<()> {
        let p = CreateDiskImageParams {
            path: path.to_path_buf(),
            gib,
        };
        self.call(method::CREATE_DISK_IMAGE, serde_json::to_value(&p)?, LONG_CALL_TIMEOUT)?;
        Ok(())
    }

    fn set_debug_logging(&self, enabled: bool) -> Result<()> {
        self.call(
            method::SET_DEBUG_LOGGING,
            json!({ "enabled": enabled }),
            SHORT_CALL_TIMEOUT,
        )?;
        Ok(())
    }

    fn is_debug_logging_enabled(&self) -> Result<bool> {
        let v = self.call(method::IS_DEBUG_LOGGING_ENABLED, json!({}), SHORT_CALL_TIMEOUT)?;
        let b: BoolValue = serde_json::from_value(v)?;
        Ok(b.value)
    }

    fn send_guest_response(&self, raw: Value) -> Result<()> {
        // TODO: implement guest-side RPC response forwarding. For now the
        // service rejects this; surface the rejection rather than silently
        // succeeding so callers can adapt.
        let _ = raw;
        Err(Error::not_implemented(
            "send_guest_response is not yet implemented on Windows",
        ))
    }

    fn passthrough(&self, method: &str, params: Value) -> Result<Value> {
        self.call(method, params, LONG_CALL_TIMEOUT)
    }

    fn add_plan9_share(&self, share: Plan9Share) -> Result<()> {
        let p = AddPlan9ShareParams { share };
        self.call(method::ADD_PLAN9_SHARE, serde_json::to_value(&p)?, LONG_CALL_TIMEOUT)?;
        Ok(())
    }

    fn remove_plan9_share(&self, name: &str) -> Result<()> {
        let p = RemovePlan9ShareParams { name: name.to_string() };
        self.call(method::REMOVE_PLAN9_SHARE, serde_json::to_value(&p)?, LONG_CALL_TIMEOUT)?;
        Ok(())
    }
}
