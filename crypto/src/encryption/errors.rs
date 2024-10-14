use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("block size has incorrect length: ({0})")]
    IncorrectBlockSize(&'static str),
}

#[derive(Debug, Error)]
pub enum DencryptionError {
    #[error("block size has incorrect length: ({0})")]
    IncorrectBlockSize(&'static str),
}
