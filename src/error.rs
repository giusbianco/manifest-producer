use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Invalid ELF file")]
    InvalidElf { #[from] source: goblin::error::Error },
}

pub type Result<T> = ::std::result::Result<T, Error>;
