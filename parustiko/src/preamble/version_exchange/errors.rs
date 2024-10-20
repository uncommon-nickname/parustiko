use thiserror::Error;

#[derive(Debug, Error)]
pub enum VersionExchangeError {
    #[error("Proto version incorrect - {0}")]
    InvalidProtoVersion(&'static str),

    #[error("{0} too long")]
    TooLongString(&'static str),

    #[error("{0}")]
    DeserializeError(&'static str),

    #[error("{0}")]
    InvalidSshMsgFormat(&'static str),
}
