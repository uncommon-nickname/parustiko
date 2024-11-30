use super::KeyExchange;
use crate::errors::VersionExchangeError;
use crate::protocol::message_ids::SshMessageID;
use std::io::Read;
use std::mem::size_of;

impl KeyExchange {
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyExchange, VersionExchangeError> {
        let mut offset = 17; //skip SSH_MSG byte (1) and cookies (16)

        let kex_algorithms = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let host_key_algorithms = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let ciphers_ctos = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let ciphers_stoc = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let macs_ctos = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let macs_stoc = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let compression_ctos = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let compression_stoc = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let languages_ctos = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;
        let languages_stoc = KeyExchange::bytes_to_vec_string(&bytes[..], &mut offset)?;

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
        output.extend(u32::to_be_bytes(self.reserved));

        output.extend([0, 0, 0]); // end message

        output
    }

    fn vec_string_to_bytes(strings: &Vec<String>) -> Vec<u8> {
        if strings.len() == 0 {
            return vec![0u8; 4];
        }

        let data_length: usize =
            strings.iter().map(|s| s.len()).sum::<usize>() + (strings.len() - 1);
        let total_length = data_length;

        let mut result = Vec::with_capacity(total_length);

        result.extend(&(total_length as u32).to_be_bytes());

        for (i, s) in strings.iter().enumerate() {
            result.extend(s.as_bytes());
            // add ',' at the end of section
            if i != strings.len() - 1 {
                result.push(44);
            }
        }

        result
    }

    // Allows to read bytes from buffer and returns decoded strings from
    // the correct section. Modifies `offset` pointer after each call, so
    // method has to be used only in `from_bytes` constructor.
    fn bytes_to_vec_string(
        section_bytes: &[u8],
        offset: &mut usize,
    ) -> Result<Vec<String>, VersionExchangeError> {
        let mut result: Vec<String> = Vec::new();
        let mut current_string: Vec<u8> = Vec::new();

        if *offset + size_of::<u32>() > section_bytes.len() {
            return Err(VersionExchangeError::OffsetOutOfRange(
                "Offset value is out of range during decoding BPP",
            ));
        }

        let section_len = u32::from_be_bytes(
            section_bytes[*offset..*offset + size_of::<u32>()]
                .try_into()
                .expect("Should not be reachable"),
        );

        *offset += size_of::<u32>();

        let section_end = *offset + section_len as usize;
        if section_end > section_bytes.len() {
            return Err(VersionExchangeError::OffsetOutOfRange(
                "The calculated section length exceeds the buffer size",
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[test]
    fn test_bytes_to_vec_string_offset_error() {
        let buffer = [1, 2, 3];
        let mut offset = 2;
        let result = KeyExchange::bytes_to_vec_string(&buffer, &mut offset);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Offset value is out of range during decoding BPP"
        );
    }

    #[test]
    fn test_bytes_to_vec_string_too_large_section_len() {
        let buffer = [128, 128, 128, 128, 128, 128, 128];
        let mut offset = 2;
        let result = KeyExchange::bytes_to_vec_string(&buffer, &mut offset);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "The calculated section length exceeds the buffer size"
        );
    }

    #[test]
    fn test_bytes_to_vec_incorrect_string() {
        let section_bytes: Vec<u8> = vec![
            0, 0, 0, 10, // msg size
            0xC0, 0xC0, 0xC0, 0xC0, 0xC0, // invalid bytes
            44,   // ,
            87, 87, 87, 87, 87, // mock to bump buffer size
        ];
        let mut offset = 0;

        let result = KeyExchange::bytes_to_vec_string(&section_bytes, &mut offset);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Read string is incorrect");
    }

    #[test]
    fn test_bytes_to_vec_correct_read_two_sections() {
        let section_bytes: Vec<u8> = vec![
            0, 0, 0, 11, // both sections size
            72, 101, 108, 108, 111, // Hello
            44,  // ,
            87, 111, 114, 108, 100, // World
        ];
        let mut offset = 0;

        let result = KeyExchange::bytes_to_vec_string(&section_bytes, &mut offset);

        assert!(result.is_ok());
        let data = result.unwrap();

        assert_eq!(data, vec!["Hello", "World"]);
    }

    #[rstest]
    #[case(vec![], vec![0u8,0u8,0u8,0u8])]
    #[case(vec!["AB".to_string(),"CDE".to_string()], vec![0,0,0,6,65,66,44,67,68,69])]
    fn test_vec_string_to_bytes(#[case] data: Vec<String>, #[case] bytes: Vec<u8>) {
        let result = KeyExchange::vec_string_to_bytes(&data);

        assert_eq!(result, bytes);
    }

    #[test]
    fn test_to_be_bytes() {
        let key_ex = KeyExchange {
            message_id: SshMessageID::KexInit,
            cookie: [0u8; 16],
            kex_algorithms: vec!["A".to_string(), "B".to_string()],
            host_key_algorithms: vec!["C".to_string(), "D".to_string()],
            ciphers_ctos: vec!["E".to_string(), "F".to_string()],
            ciphers_stoc: vec!["G".to_string(), "H".to_string()],
            macs_ctos: vec!["I".to_string(), "J".to_string()],
            macs_stoc: vec!["K".to_string(), "L".to_string()],
            compression_ctos: vec!["M".to_string(), "N".to_string()],
            compression_stoc: vec!["O".to_string(), "P".to_string()],
            languages_ctos: vec!["Q".to_string(), "R".to_string()],
            languages_stoc: vec!["S".to_string(), "T".to_string()],
            first_kex_follows: false,
            reserved: 0u32,
        };
        let result = key_ex.to_be_bytes();

        assert_eq!(
            result,
            Vec::from([
                20, //ssh msg id
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // cookie
                0, 0, 0, 3, // kex algo size
                65, 44, 66, // kex algo msg
                0, 0, 0, 3, // host keys algo size
                67, 44, 68, // host keys algo msg
                0, 0, 0, 3, // cipher ctos size
                69, 44, 70, // cipher ctos msg
                0, 0, 0, 3, // cipher stos size
                71, 44, 72, // cipher stos msg
                0, 0, 0, 3, // mac ctos size
                73, 44, 74, // mac ctos msg
                0, 0, 0, 3, // mac stoc size
                75, 44, 76, // mac stoc msg
                0, 0, 0, 3, // comp ctos size
                77, 44, 78, // comp ctos msg
                0, 0, 0, 3, // comp stoc size
                79, 44, 80, // comp stoc msg
                0, 0, 0, 3, // language ctos size
                81, 44, 82, // language ctos msg
                0, 0, 0, 3, // language stoc size
                83, 44, 84, // language stoc msg
                0,  // first_kex_follows
                0, 0, 0, 0, //reserved
                0, 0, 0 // end msg
            ])
        )
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [
            20, //ssh msg id
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // cookie
            0, 0, 0, 3, // kex algo size
            65, 44, 66, // kex algo msg
            0, 0, 0, 3, // host keys algo size
            67, 44, 68, // host keys algo msg
            0, 0, 0, 3, // cipher ctos size
            69, 44, 70, // cipher ctos msg
            0, 0, 0, 3, // cipher stos size
            71, 44, 72, // cipher stos msg
            0, 0, 0, 3, // mac ctos size
            73, 44, 74, // mac ctos msg
            0, 0, 0, 3, // mac stoc size
            75, 44, 76, // mac stoc msg
            0, 0, 0, 3, // comp ctos size
            77, 44, 78, // comp ctos msg
            0, 0, 0, 3, // comp stoc size
            79, 44, 80, // comp stoc msg
            0, 0, 0, 3, // language ctos size
            81, 44, 82, // language ctos msg
            0, 0, 0, 3, // language stoc size
            83, 44, 84, // language stoc msg
        ];

        let result = KeyExchange::from_bytes(&bytes);
        assert!(result.is_ok());

        let key_ex = result.unwrap();
        assert_eq!(key_ex.message_id as u32, 20);
        assert_eq!(key_ex.cookie, [0u8; 16]);
        assert_eq!(
            key_ex.kex_algorithms,
            vec!["A".to_string(), "B".to_string()]
        );
        assert_eq!(
            key_ex.host_key_algorithms,
            vec!["C".to_string(), "D".to_string()]
        );
        assert_eq!(key_ex.ciphers_ctos, vec!["E".to_string(), "F".to_string()]);
        assert_eq!(key_ex.ciphers_stoc, vec!["G".to_string(), "H".to_string()]);
        assert_eq!(key_ex.macs_ctos, vec!["I".to_string(), "J".to_string()]);
        assert_eq!(key_ex.macs_stoc, vec!["K".to_string(), "L".to_string()]);
        assert_eq!(
            key_ex.compression_ctos,
            vec!["M".to_string(), "N".to_string()]
        );
        assert_eq!(
            key_ex.compression_stoc,
            vec!["O".to_string(), "P".to_string()]
        );
        assert_eq!(
            key_ex.languages_ctos,
            vec!["Q".to_string(), "R".to_string()]
        );
        assert_eq!(
            key_ex.languages_stoc,
            vec!["S".to_string(), "T".to_string()]
        );
        assert_eq!(key_ex.first_kex_follows, false);
        assert_eq!(key_ex.reserved, 0u32);
    }
}
