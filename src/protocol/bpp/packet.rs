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
    pub fn try_build(
        padding_length: u8,
        payload: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_BINARY_PROTOCOL_PAYLOAD_SIZE_BYTES {
            return Err(ProtocolError::BinaryProtocolInvalidEntity(
                "payload is too long for SSH message",
            ));
        }

        if padding_length < MIN_PADDING_SIZE_BYTES {
            return Err(ProtocolError::BinaryProtocolInvalidEntity(
                "padding is too short for SSH message",
            ));
        }

        let message_id = SSHMessageID::from_u8(payload[0]).ok_or(
            ProtocolError::BinaryProtocolInvalidEntity("unknown SSH message ID"),
        )?;
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

        if buff.len() != expected_buff_size {
            Err(ProtocolError::BinaryProtocolEncodingFailed(
                "final buffer has incorrect length",
            ))
        } else {
            Ok(buff)
        }
    }

    fn encoded_len(&self) -> usize {
        // 4 bytes of encoded packet length.
        size_of::<u32>() +
        // 1 byte of encoded padding length + payload + padding
        self.packet_length as usize +
        // n bytes of encoded mac length
        self.mac_length as usize
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

        Self::Entity::try_build(padding_length, payload, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn message() -> BinaryProtocolMessage {
        BinaryProtocolMessage {
            message_id: SSHMessageID::KexInit,
            packet_length: 50,
            padding_length: 25,
            mac_length: 8,
            payload: vec![0_u8; 24],
            mac: vec![1_u8; 8],
        }
    }

    #[rstest]
    #[case(
        vec![0_u8; 33_000], 25, "entity preconditions are not met: (payload is too long for SSH message)"
    )]
    #[case(
        vec![0_u8; 5], 3, "entity preconditions are not met: (padding is too short for SSH message)"
    )]
    #[case(
        vec![0_u8; 5], 25, "entity preconditions are not met: (unknown SSH message ID)"
    )]
    fn build_protocol_message_errors(
        #[case] payload: Vec<u8>,
        #[case] padding_length: u8,
        #[case] err_str: &str,
    ) {
        let result = BinaryProtocolMessage::try_build(padding_length, payload, vec![0_u8; 5])
            .unwrap_err()
            .to_string();

        assert_eq!(result, err_str);
    }

    #[test]
    fn build_protocol_message() {
        let payload = vec![20_u8, 30, 40, 50];
        let mac = vec![0_u8; 5];

        let message = BinaryProtocolMessage::try_build(020, payload, mac).unwrap();

        assert_eq!(message.message_id, SSHMessageID::KexInit);
        assert_eq!(message.packet_length, 4 + 20 + 1)
    }

    #[rstest]
    fn build_random_padding_size(message: BinaryProtocolMessage) {
        let pad = message.build_random_padding();

        assert_eq!(message.padding_length as usize, pad.len());
    }
}
