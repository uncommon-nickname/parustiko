use super::KeyExchange;
use crate::errors::VersionExchangeError;
use crate::protocol::message_ids::SshMessageID;
use std::io::Read;
use std::mem::size_of;

impl KeyExchange {
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyExchange, VersionExchangeError> {
        let mut offset = 17; //skip SSH_MSG byte (1) and cookies (16)

        let kex_algorithms = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let host_key_algorithms = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let ciphers_ctos = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let ciphers_stoc = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let macs_ctos = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let macs_stoc = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let compression_ctos = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let compression_stoc = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let languages_ctos = KeyExchange::parse_section(&bytes[..], &mut offset)?;
        let languages_stoc = KeyExchange::parse_section(&bytes[..], &mut offset)?;

        Ok(KeyExchange {
            message_id: SshMessageID::KexInit,
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

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();

        output.push(SshMessageID::KexInit as u8);
        output.extend_from_slice(&self.cookie);

        output.extend(KeyExchange::vec_string_to_bytes(&self.kex_algorithms));
        output.extend(KeyExchange::vec_string_to_bytes(&self.host_key_algorithms));
        output.extend(KeyExchange::vec_string_to_bytes(&self.ciphers_ctos));
        output.extend(KeyExchange::vec_string_to_bytes(&self.ciphers_stoc));
        output.extend(KeyExchange::vec_string_to_bytes(&self.macs_ctos));
        output.extend(KeyExchange::vec_string_to_bytes(&self.macs_stoc));
        output.extend(KeyExchange::vec_string_to_bytes(&self.compression_ctos));
        output.extend(KeyExchange::vec_string_to_bytes(&self.compression_stoc));
        output.extend(KeyExchange::vec_string_to_bytes(&self.languages_ctos));
        output.extend(KeyExchange::vec_string_to_bytes(&self.languages_stoc));
        output.push(self.first_kex_follows as u8);
        output.push(self.reserved as u8); //TODO! endianness

        output
    }

    fn vec_string_to_bytes(strings: &Vec<String>) -> Vec<u8> {
        if strings.len() == 0 {
            return vec![0u8; 4];
        }
        let data_length: usize =
            strings.iter().map(|s| s.len()).sum::<usize>() + (strings.len() - 1);
        let total_length = data_length + 4 + 3;

        let mut result = Vec::with_capacity(total_length);

        result.extend(&(total_length as u32).to_be_bytes());

        for (i, s) in strings.iter().enumerate() {
            result.extend(s.as_bytes());
            if i != strings.len() - 1 {
                result.push(44);
            }
        }

        result.extend([0, 0, 0]);

        result
    }

    fn parse_section(
        section_bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Vec<String>, VersionExchangeError> {
        let mut result: Vec<String> = Vec::new();
        let mut current_string: Vec<u8> = Vec::new();
        let section_len = u32::from_be_bytes(
            section_bytes[*offset..*offset + size_of::<u32>()]
                .try_into()
                .map_err(|_e| {
                    VersionExchangeError::OffsetOutOfRange(
                        "offset value is out of range during decoding BPP",
                    )
                })?,
        );

        *offset += size_of::<u32>();

        let section_end = *offset + section_len as usize;
        for byte in &section_bytes[*offset..section_end] {
            // found ','
            if *byte == 44 {
                if !current_string.is_empty() {
                    result.push(String::from_utf8(current_string.clone()).map_err(|_e| {
                        VersionExchangeError::InvalidString("Read string is incorrect")
                    })?);
                    current_string.clear();
                }
            } else {
                current_string.push(*byte);
            }
        }

        if !current_string.is_empty() {
            result.push(
                String::from_utf8(current_string).map_err(|_e| {
                    VersionExchangeError::InvalidString("Read string is incorrect")
                })?,
            );
        }

        *offset = section_end;
        Ok(result)
    }
}
