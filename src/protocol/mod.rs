mod bpp;
mod message;

use crate::errors::ProtocolError;

use std::io::Read;

pub trait Encode {
    // Consume the entity and return it BE byte representation.
    fn encode_to_bytes(self) -> Result<Vec<u8>, ProtocolError>;

    // Calculate the size of BE byte representation.
    fn encoded_len(&self) -> usize;
}

pub trait Decode {
    type Entity;

    // Construct the entity from BE byte representation.
    fn decode_from_bytes(buffer: Vec<u8>) -> Result<Self::Entity, ProtocolError>;
}

pub trait DecodeRaw {
    type Entity;

    // Construct the entity from readable buffer.
    fn decode_from_reader<R: Read>(
        buffer: R,
        mac_length: u8,
    ) -> Result<Self::Entity, ProtocolError>;
}
