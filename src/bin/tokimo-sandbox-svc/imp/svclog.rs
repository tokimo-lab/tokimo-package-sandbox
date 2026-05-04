//! File logger for the Windows service.
//!
//! Appends to `%ProgramData%\tokimo-sandbox\svc.log` and mirrors every line
//! to stderr so console mode keeps working. All I/O errors are silently
//! swallowed — logging must never disrupt the service.
//!
//! Format: `2026-04-05T13:45:12.345Z [tid=1234] <message>`

use std::fs::{File, OpenOptions, rename};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

static LOG_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn open_log() -> Option<Mutex<File>> {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let dir = PathBuf::from(base).join("tokimo-sandbox");
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let path = dir.join("svc.log");
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > MAX_LOG_BYTES
    {
        let _ = rename(&path, dir.join("svc.log.1"));
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
        .map(Mutex::new)
}

pub fn init_log() {
    LOG_FILE.get_or_init(open_log);
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn format_timestamp_utc(now: SystemTime) -> String {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total = dur.as_secs();
    let s = (total % 60) as u32;
    let m = ((total / 60) % 60) as u32;
    let h = ((total / 3600) % 24) as u32;
    let mut days = (total / 86_400) as i64;
    let mut year: i64 = 1970;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    const MD: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month: u32 = 1;
    let mut d = days as u32;
    for (i, &md) in MD.iter().enumerate() {
        let md = if i == 1 && is_leap(year) { 29 } else { md };
        if d < md {
            break;
        }
        d -= md;
        month += 1;
    }
    let day = d + 1;
    let ms = dur.subsec_millis();
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

fn thread_id_num() -> u64 {
    let s = format!("{:?}", std::thread::current().id());
    s.trim_start_matches("ThreadId(")
        .trim_end_matches(')')
        .parse()
        .unwrap_or(0)
}

pub fn log_line(msg: &str) {
    let line = format!(
        "{} [tid={}] {}",
        format_timestamp_utc(SystemTime::now()),
        thread_id_num(),
        msg
    );
    eprintln!("{line}");
    if let Some(Some(mu)) = LOG_FILE.get()
        && let Ok(mut f) = mu.lock()
    {
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }
}

macro_rules! slog {
    ($($arg:tt)*) => {{
        $crate::imp::svclog::log_line(&format!($($arg)*));
    }};
}
pub(crate) use slog;
