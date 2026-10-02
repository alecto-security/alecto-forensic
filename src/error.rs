use thiserror::Error;

pub const EXIT_OK: i32 = 0;
/// Package written, but gaps were recorded.
pub const EXIT_PARTIAL: i32 = 1;
pub const EXIT_FAIL: i32 = 2;
pub const EXIT_CONFIG: i32 = 3;

#[derive(Debug, Error)]
pub enum ForensicError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Fail(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl ForensicError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn fail(msg: impl Into<String>) -> Self {
        Self::Fail(msg.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => EXIT_CONFIG,
            _ => EXIT_FAIL,
        }
    }
}

pub type Result<T> = std::result::Result<T, ForensicError>;
