use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BppError {
    #[error("encoding message to bytes failed: ({0})")]
    EncodingFailed(&'static str),

    #[error("decoding binary protocol from message failed: {0:?}")]
    DecodingFailed(#[from] io::Error),

    #[error("entity preconditions are not met: ({0})")]
    InvalidEntity(&'static str),
}

#[derive(Debug, Error)]
pub enum VersionExchangeError {
    #[error("Proto version incorrect - {0}")]
    InvalidProtoVersion(&'static str),

    #[error("{0}")]
    InvalidString(&'static str),

    #[error("{0}")]
    InvalidSshMsgFormat(&'static str),

    #[error("{0}")]
    EmptyStream(String),

    #[error("{0}")]
    OffsetOutOfRange(&'static str),
}
