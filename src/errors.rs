use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("encoding message to bytes failed: ({0})")]
    BinaryProtocolEncodingFailed(&'static str),

    #[error("decoding binary protocol from message failed: {0:?}")]
    BinaryProtocolDecodingFailed(#[from] io::Error),

    #[error("entity preconditions are not met: ({0})")]
    BinaryProtocolInvalidEntity(&'static str),
}
