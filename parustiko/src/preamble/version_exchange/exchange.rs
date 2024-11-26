use super::errors::VersionExchangeError;
use super::KeyExchange;
use std::io::Read;
use std::mem::size_of;

impl KeyExchange {
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyExchange, VersionExchangeError> {
        let mut offset = 17; //skip SSH_MSG byte and cookies

        let kex_algorithms = KeyExchange::parse_section(&bytes[..], &mut offset);
        let host_key_algorithms = KeyExchange::parse_section(&bytes[..], &mut offset);
        let ciphers_ctos = KeyExchange::parse_section(&bytes[..], &mut offset);
        let ciphers_stoc = KeyExchange::parse_section(&bytes[..], &mut offset);
        let macs_ctos = KeyExchange::parse_section(&bytes[..], &mut offset);
        let macs_stoc = KeyExchange::parse_section(&bytes[..], &mut offset);
        let compression_ctos = KeyExchange::parse_section(&bytes[..], &mut offset);
        let compression_stoc = KeyExchange::parse_section(&bytes[..], &mut offset);
        let languages_ctos = KeyExchange::parse_section(&bytes[..], &mut offset);
        let languages_stoc = KeyExchange::parse_section(&bytes[..], &mut offset);

        Ok(KeyExchange {
            message_id: 20,
            cookie: [0u8; 16],
            kex_algorithms,
            host_key_algorithms,
            ciphers_ctos,
            ciphers_stoc,
            macs_ctos,
            macs_stoc,
            compression_ctos,
            compression_stoc,
            languages_ctos,
            languages_stoc,
            first_kex_follows: false,
            reserved: 0,
        })
    }

    fn parse_section(section_bytes: &[u8], offset: &mut usize) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        let mut current_string: Vec<u8> = Vec::new();
        let section_len =
            u32::from_be_bytes(section_bytes[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;

        let section_end = *offset + section_len as usize;
        for byte in &section_bytes[*offset..section_end] {
            if *byte == 44 {
                if !current_string.is_empty() {
                    result.push(String::from_utf8(current_string.clone()).unwrap());
                    current_string.clear();
                }
            } else {
                current_string.push(*byte);
            }
        }

        if !current_string.is_empty() {
            result.push(String::from_utf8(current_string).unwrap());
        }

        *offset = section_end;
        result
    }
}
