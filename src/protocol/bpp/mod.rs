mod packet;

use crate::protocol::message::SSHMessageID;

#[derive(Debug)]
pub struct BinaryProtocolMessage {
    message_id: SSHMessageID,
    packet_length: u32,
    padding_length: u8,
    mac_length: u8,
    payload: Vec<u8>,
    mac: Vec<u8>,
}
