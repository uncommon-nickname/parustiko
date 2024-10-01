use super::BinaryProtocolMessage;

use crate::errors::ProtocolError;
use crate::protocol::message::SSHMessageID;
use crate::protocol::{DecodeRaw, Encode};

use num_traits::FromPrimitive;
use rand::Rng;
use std::io::Read;
use std::mem::size_of;

const MAX_BINARY_PROTOCOL_PAYLOAD_SIZE_BYTES: usize = 32_768;
const MIN_PADDING_SIZE_BYTES: u8 = 4;

impl BinaryProtocolMessage {
    pub fn new(padding_length: u8, payload: Vec<u8>, mac: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_BINARY_PROTOCOL_PAYLOAD_SIZE_BYTES
            || padding_length < MIN_PADDING_SIZE_BYTES
        {
            return Err(ProtocolError::InvalidEntity);
        }

        let message_id = SSHMessageID::from_u8(payload[0]).ok_or(ProtocolError::InvalidEntity)?;
        let packet_length = payload.len() as u32 + padding_length as u32 + 1;
        let mac_length = mac.len() as u8;

        Ok(Self {
            message_id,
            packet_length,
            padding_length,
            mac_length,
            payload,
            mac,
        })
    }

    fn build_random_padding(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..self.padding_length).map(|_| rng.gen()).collect()
    }
}

impl Encode for BinaryProtocolMessage {
    fn encode_to_bytes(mut self) -> Result<Vec<u8>, ProtocolError> {
        let expected_buff_size = self.encoded_len();
        let mut buff = Vec::with_capacity(expected_buff_size);

        let encoded_packet_length = self.packet_length.to_be_bytes();
        buff.extend_from_slice(&encoded_packet_length);

        let encoded_padding_length = self.padding_length.to_be();
        buff.push(encoded_padding_length);

        buff.append(&mut self.payload);

        let mut random_padding = self.build_random_padding();
        buff.append(&mut random_padding);

        buff.append(&mut self.mac);

        Ok(buff)
    }

    fn encoded_len(&self) -> usize {
        size_of::<u32>() + self.packet_length as usize + self.mac.len()
    }
}

impl DecodeRaw for BinaryProtocolMessage {
    type Entity = Self;

    fn decode_from_reader<R: Read>(
        mut buffer: R,
        mac_length: u8,
    ) -> Result<Self::Entity, ProtocolError> {
        let mut packet_length = [0_u8; 4];
        buffer.read_exact(&mut packet_length)?;

        let packet_length = u32::from_be_bytes(packet_length) as usize;

        let mut padding_length = [0_u8];
        buffer.read_exact(&mut padding_length)?;

        let padding_length = u8::from_be_bytes(padding_length);
        let payload_length = packet_length - padding_length as usize - 1;

        let mut payload = vec![0_u8; payload_length];
        buffer.read_exact(&mut payload)?;

        let mac = match mac_length > 0 {
            true => {
                let mut mac = vec![0_u8; mac_length as usize];
                buffer.read_exact(&mut mac)?;
                mac
            }
            false => vec![],
        };

        Self::Entity::new(padding_length, payload, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
