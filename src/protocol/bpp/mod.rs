mod packet;

use crate::protocol::message::SshMessageID;

#[derive(Debug)]
pub struct BinaryProtoPacket {
    message_id: SshMessageID,
    packet_length: u32,
    padding_length: u8,
    mac_length: u8,
    payload: Vec<u8>,
    mac: Vec<u8>,
}
