mod bpp;
mod message;

use crate::errors::ProtocolError;

use std::io::Read;

pub trait Encode {
    // Consume the entity and return it's BE byte representation.
    fn to_be_bytes(self) -> Result<Vec<u8>, ProtocolError>;

    // Calculate the size of BE byte representation.
    fn size(&self) -> usize;
}

pub trait Decode {
    type Entity;

    // Construct the entity from it's BE byte representation.
    fn from_be_bytes(buffer: Vec<u8>) -> Result<Self::Entity, ProtocolError>;
}

pub trait DecodeRaw {
    type Entity;

    // Construct the entity from readable buffer.
    fn from_be_bytes<R: Read>(buffer: R, mac_size: u8) -> Result<Self::Entity, ProtocolError>;
}
