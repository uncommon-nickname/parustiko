use super::BinaryProtocolPacket;

use crate::errors::ProtocolError;
use crate::protocol::message::SshMessageID;
use crate::protocol::{DecodeRaw, Encode};

use num_traits::FromPrimitive;
use rand::Rng;
use std::io::Read;
use std::mem::size_of;

const MAX_BINARY_PROTOCOL_PAYLOAD_SIZE_BYTES: usize = 32_768;
const MIN_PADDING_SIZE_BYTES: u8 = 4;

impl BinaryProtocolPacket {
    pub fn try_build(
        padding_length: u8,
        payload: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_BINARY_PROTOCOL_PAYLOAD_SIZE_BYTES {
            return Err(ProtocolError::BinaryPacketInvalidEntity(
                "payload is too long for SSH message",
            ));
        }

        if padding_length < MIN_PADDING_SIZE_BYTES {
            return Err(ProtocolError::BinaryPacketInvalidEntity(
                "padding is too short for SSH message",
            ));
        }

        let message_id = SshMessageID::from_u8(payload[0]).ok_or(
            ProtocolError::BinaryPacketInvalidEntity("unknown SSH message ID"),
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

impl Encode for BinaryProtocolPacket {
    // SSH protocol utilizes the network endianness, so the packets
    // should be encoded with big endian.
    fn to_be_bytes(mut self) -> Result<Vec<u8>, ProtocolError> {
        let expected_buff_size = self.size();
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
            return Err(ProtocolError::BinaryPacketEncodingFailed(
                "final buffer has incorrect length",
            ));
        }

        Ok(buff)
    }

    fn size(&self) -> usize {
        // 4 bytes of encoded packet length.
        size_of::<u32>() +
        // 1 byte of encoded padding length + payload + padding
        self.packet_length as usize +
        // n bytes of encoded mac length
        self.mac_length as usize
    }
}

impl DecodeRaw for BinaryProtocolPacket {
    type Entity = Self;

    fn from_be_bytes<R: Read>(mut buffer: R, mac_size: u8) -> Result<Self::Entity, ProtocolError> {
        let mut packet_length = [0_u8; 4];
        buffer.read_exact(&mut packet_length)?;

        let packet_length = u32::from_be_bytes(packet_length) as usize;

        let mut padding_length = [0_u8];
        buffer.read_exact(&mut padding_length)?;

        let padding_length = u8::from_be_bytes(padding_length);
        let payload_length = packet_length - padding_length as usize - 1;

        let mut payload = vec![0_u8; payload_length];
        buffer.read_exact(&mut payload)?;

        let mut padding = vec![0_u8; padding_length as usize];
        buffer.read_exact(&mut padding)?;

        let mac = if mac_size > 0 {
            let mut _mac = vec![0_u8; mac_size as usize];
            buffer.read_exact(&mut _mac)?;
            _mac
        } else {
            vec![]
        };

        Self::Entity::try_build(padding_length, payload, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn message() -> BinaryProtocolPacket {
        BinaryProtocolPacket {
            message_id: SshMessageID::KexInit,
            packet_length: 50,
            padding_length: 25,
            mac_length: 8,
            payload: vec![0_u8; 24],
            mac: vec![1_u8; 8],
        }
    }

    #[fixture]
    fn raw_buffer() -> Vec<u8> {
        vec![
            0_u8, 0, 0, 6,  // Packet size.
            4,  // Padding size.
            20, // Payload.
            2, 3, 4, 5, // Padding.
            6, 7, // Mac.
        ]
    }

    #[rstest]
    #[case(vec![0_u8; 33_000], 25, "payload is too long for SSH message")]
    #[case(vec![0_u8; 5], 3, "padding is too short for SSH message")]
    #[case(vec![0_u8; 5], 25, "unknown SSH message ID")]
    fn build_protocol_message_errors(
        #[case] payload: Vec<u8>,
        #[case] padding_length: u8,
        #[case] err_str: &str,
    ) {
        let err = BinaryProtocolPacket::try_build(padding_length, payload, vec![0_u8; 5])
            .unwrap_err()
            .to_string();

        assert_eq!(
            err,
            format!("entity preconditions are not met: ({})", err_str)
        );
    }

    #[test]
    fn build_protocol_message() {
        let payload = vec![20_u8, 30, 40, 50];
        let mac = vec![0_u8; 5];

        let message = BinaryProtocolPacket::try_build(020, payload, mac).unwrap();

        assert_eq!(message.message_id, SshMessageID::KexInit);
        assert_eq!(message.packet_length, 4 + 20 + 1)
    }

    #[rstest]
    fn build_random_padding_size(message: BinaryProtocolPacket) {
        let pad = message.build_random_padding();

        assert_eq!(message.padding_length as usize, pad.len());
    }

    #[rstest]
    fn encode_to_bytes_wrong_final_length(mut message: BinaryProtocolPacket) {
        message.mac_length = 13;

        let err = message.to_be_bytes().unwrap_err().to_string();

        assert_eq!(
            err,
            "encoding message to bytes failed: (final buffer has incorrect length)"
        );
    }

    #[rstest]
    fn encode_to_bytes(message: BinaryProtocolPacket) {
        let original_payload = message.payload.clone();
        let original_mac = message.mac.clone();

        let buff = message.to_be_bytes().unwrap();

        assert_eq!(buff[..4], [0, 0, 0, 50]);
        assert_eq!(buff[4..5], [25]);
        assert_eq!(buff[5..29], original_payload);
        assert_eq!(buff[54..], original_mac);
    }

    #[rstest]
    fn calculate_encoded_length(message: BinaryProtocolPacket) {
        let length = message.size();

        assert_eq!(
            length,
            4 + 1 + message.payload.len() + message.padding_length as usize + message.mac.len(),
        )
    }

    #[rstest]
    #[case(3)] // One byte short to read packet size.
    #[case(4)] // One byte short to read padding size.
    #[case(5)] // One byte short to read payload.
    #[case(9)] // One byte short to read padding.
    #[case(11)] // One byte short to read mac.
    fn decode_not_enough_data_in_buffer(raw_buffer: Vec<u8>, #[case] stop: usize) {
        let err = BinaryProtocolPacket::from_be_bytes(&raw_buffer[..stop], 2)
            .unwrap_err()
            .to_string();

        assert_eq!(err, "decoding binary protocol from message failed: Error { kind: UnexpectedEof, message: \"failed to fill whole buffer\" }");
    }

    #[rstest]
    fn decode_buffer_into_packet_object(raw_buffer: Vec<u8>) {
        let message = BinaryProtocolPacket::from_be_bytes(&raw_buffer[..], 2).unwrap();

        assert_eq!(message.message_id, SshMessageID::KexInit);
        assert_eq!(message.packet_length, 6);
        assert_eq!(message.padding_length, 4);
        assert_eq!(message.payload, [20]);
        assert_eq!(message.mac_length, 2);
        assert_eq!(message.mac, [6, 7]);
    }
}
