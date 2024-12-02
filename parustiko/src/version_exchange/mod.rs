pub mod exchange;
pub mod version;
use crate::protocol::message_ids::SshMessageID;

#[derive(Debug)]
pub struct SshVersion {
    proto_version: String,
    software_version: String,
    comments: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyExchange {
    message_id: SshMessageID,
    cookie: [u8; 16],
    kex_algorithms: Vec<String>,
    host_key_algorithms: Vec<String>,
    ciphers_ctos: Vec<String>,
    ciphers_stoc: Vec<String>,
    macs_ctos: Vec<String>,
    macs_stoc: Vec<String>,
    compression_ctos: Vec<String>,
    compression_stoc: Vec<String>,
    languages_ctos: Vec<String>,
    languages_stoc: Vec<String>,
    first_kex_follows: bool,
    reserved: u32,
}
