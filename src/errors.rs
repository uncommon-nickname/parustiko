use std::io::Error as IoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Encoding message to bytes failed.")]
    EncodingFailed,

    #[error("Decoding message from bytes failed.")]
    DecodingFailed,

    #[error("Entity preconditions are not set.")]
    InvalidEntity,

    #[error("Reading from raw buffer failed. {0:?}")]
    ReadError(#[from] IoError),
}
