//! Error types for the public Sandbox API.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("not connected to sandbox service")]
    NotConnected,

    #[error("vm is not running")]
    VmNotRunning,

    #[error("vm is already running")]
    VmAlreadyRunning,

    #[error("not configured (call configure() first)")]
    NotConfigured,

    #[error("method not supported on this platform: {0}")]
    NotSupported(String),

    #[error("method not yet implemented: {0}")]
    NotImplemented(String),

    #[error("rpc error [{code}]: {message}")]
    Rpc { code: String, message: String },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("guest error: {0}")]
    Guest(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }
    pub fn rpc(code: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Rpc {
            code: code.into(),
            message: message.into(),
        }
    }
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
    pub fn not_supported(what: impl Into<String>) -> Self {
        Error::NotSupported(what.into())
    }
    pub fn not_implemented(what: impl Into<String>) -> Self {
        Error::NotImplemented(what.into())
    }
    /// Alias for `other()` — used by InitClient for exec-related errors.
    pub fn exec(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::Error::other(format!($($arg)*))); };
}
