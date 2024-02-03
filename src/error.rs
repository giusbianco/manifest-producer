use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Invalid ELF file")]
    InvalidElf { #[from] source: goblin::error::Error },

    #[error("JSON serialization error")]
    Json(#[from] serde_json::Error),

    #[error("No system call section")]
    NoSyscallSec,
}

pub type Result<T> = ::std::result::Result<T, Error>;
