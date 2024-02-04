use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Invalid ELF file")]
    InvalidElf { #[from] source: goblin::error::Error },

    #[error("JSON serialization error")]
    Json(#[from] serde_json::Error),

    /*#[error("Capstone error: {0}")]
    Capstone(String),*/

    #[error("No system call section")]
    NoSyscallSec,
}
/*impl From<capstone::Error> for Error {
    fn from(err: capstone::Error) -> Self {
        Error::Capstone(err.to_string())
    }
}*/

pub type Result<T> = ::std::result::Result<T, Error>;
