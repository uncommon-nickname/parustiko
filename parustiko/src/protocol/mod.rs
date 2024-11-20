mod binary_packet;
mod message_ids;

use crate::errors::BppError;
use message_ids::SshMessageID;

use std::io::Read;

#[derive(Debug)]
pub struct BinaryProtocolPacket {
    message_id: SshMessageID,
    packet_length: u32,
    padding_length: u8,
    mac_length: u8,
    payload: Vec<u8>,
    mac: Vec<u8>,
}

pub trait Encode {
    // Consume the entity and return it's BE byte representation.
    fn to_be_bytes(self) -> Result<Vec<u8>, BppError>;

    // Calculate the size of BE byte representation.
    fn size(&self) -> usize;
}

pub trait Decode {
    type Entity;

    // Construct the entity from it's BE byte representation.
    fn from_be_bytes(buffer: Vec<u8>) -> Result<Self::Entity, BppError>;
}

pub trait DecodeRaw {
    type Entity;

    // Construct the entity from readable buffer.
    fn from_be_bytes<R: Read>(buffer: R, mac_size: u8) -> Result<Self::Entity, BppError>;
}
