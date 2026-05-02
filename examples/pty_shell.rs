//! Interactive PTY shell inside a sandbox VM.
//!
//! Prerequisites (Windows):
//!   - tokimo-sandbox-svc.exe running (admin, --console or SCM)
//!   - VM artifacts in vm/
//!
//! Usage:
//!   cargo run --example pty_shell

use std::io::{self, Read, Write};
use std::thread;

use tokimo_package_sandbox::{ConfigureParams, Mount, Sandbox, ShellOpts};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sb = Sandbox::connect()?;
    let cwd = std::env::current_dir()?;
    sb.configure(ConfigureParams {
        user_data_name: "pty-shell".into(),
        memory_mb: 4096,
        cpu_count: 4,
        mounts: vec![Mount {
            name: "work".into(),
            host_path: cwd,
            guest_path: "/work".into(),
            read_only: false,
        }],
        ..Default::default()
    })?;
    sb.create_vm()?;
    sb.start_vm()?;

    let (cols, rows) = terminal_size();
    let shell = sb.spawn_shell(ShellOpts {
        pty: Some((rows, cols)),
        ..Default::default()
    })?;

    let rx = sb.subscribe()?;

    // PTY output → stdout (dedicated thread)
    let stdout_thread = {
        let rx = rx; // move rx into this thread
        thread::spawn(move || {
            let mut out = io::stdout().lock();
            let mut shell_exited = false;
            for ev in rx {
                match ev {
                    tokimo_package_sandbox::Event::Stdout { data, .. } => {
                        let _ = out.write_all(&data);
                        let _ = out.flush();
                    }
                    tokimo_package_sandbox::Event::Exit { exit_code, .. } => {
                        eprintln!("\n[shell exited: {exit_code}]");
                        shell_exited = true;
                        break;
                    }
                    tokimo_package_sandbox::Event::Error { message, .. } => {
                        eprintln!("\n[error: {message}]");
                    }
                    _ => {}
                }
            }
            shell_exited
        })
    };

    // stdin → PTY input (blocking read on this thread)
    enable_raw_mode();
    let mut stdin = io::stdin().lock();
    let mut buf = [0u8; 1024];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Ctrl-D → exit
                if buf[..n].contains(&0x04) {
                    break;
                }
                if sb.write_stdin(&shell, &buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    disable_raw_mode();

    // Send EOF to let the shell exit naturally, then wait for the Exit event.
    // If it doesn't exit in 3s, force-kill.
    let _ = sb.write_stdin(&shell, &[0x04]); // Ctrl-D
    let exited = {
        let handle = stdout_thread;
        // Give the shell up to 3 seconds to exit after EOF
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if handle.is_finished() {
                break handle.join().unwrap_or(false);
            }
            if std::time::Instant::now() > deadline {
                let _ = sb.signal_shell(&shell, 9);
                break handle.join().unwrap_or(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };
    let _ = sb.stop_vm();
    if !exited {
        std::process::exit(1);
    }
    Ok(())
}

// ── Terminal helpers ─────────────────────────────────────────────────────────

#[cfg(windows)]
fn terminal_size() -> (u16, u16) {
    use windows::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(h, &mut info).is_ok() {
            let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
            let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
            return (cols.max(80), rows.max(24));
        }
    }
    (80, 24)
}

#[cfg(not(windows))]
fn terminal_size() -> (u16, u16) {
    (80, 24)
}

#[cfg(windows)]
fn enable_raw_mode() {
    use windows::Win32::System::Console::{ENABLE_PROCESSED_INPUT, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
        // Disable line buffering and echo
        let _ = SetConsoleMode(h, ENABLE_PROCESSED_INPUT);
    }
}

#[cfg(windows)]
fn disable_raw_mode() {
    use windows::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
        let _ = SetConsoleMode(h, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    }
}

#[cfg(not(windows))]
fn enable_raw_mode() {}

#[cfg(not(windows))]
fn disable_raw_mode() {}
