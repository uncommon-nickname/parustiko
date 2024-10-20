mod errors;
mod packet;

#[derive(Debug)]
pub struct SshVersionExchange {
    proto_version: String,
    software_version: String,
    comments: Option<String>,
}
