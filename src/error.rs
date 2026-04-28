use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("sandbox tool not found: {0}")]
    ToolNotFound(String),

    #[error("sandbox execution failed: {0}")]
    Exec(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }
    pub fn exec(msg: impl Into<String>) -> Self {
        Error::Exec(msg.into())
    }
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::Error::exec(format!($($arg)*))); };
}

/// Result of running a command inside the sandbox.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    /// Process exit code, or -1 if the process was killed by the sandbox.
    pub exit_code: i32,
    /// True if the sandbox killed the process due to timeout.
    pub timed_out: bool,
    /// True if the sandbox killed the process due to memory overrun.
    pub oom_killed: bool,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out && !self.oom_killed
    }
}
