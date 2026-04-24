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
