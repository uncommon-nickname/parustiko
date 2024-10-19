use super::errors::{DecryptionError, EncryptionError};
use super::Encryption;
pub use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

pub struct AES {
    pub cipher: Aes128,
}

impl AES {
    pub fn new() -> Self {
        let key = GenericArray::from([0u8; 16]);

        AES {
            cipher: Aes128::new(&key),
        }
    }
}

impl Default for AES {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryption for AES {
    fn encrypt(&self, block: &mut [u8]) -> Result<(), EncryptionError> {
        if block.len() != 16 {
            return Err(EncryptionError::IncorrectBlockSize(
                "block size has to have 16 bytes",
            ));
        }

        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(block));

        Ok(())
    }

    fn decrypt(&self, block: &mut [u8]) -> Result<(), DecryptionError> {
        if block.len() != 16 {
            return Err(DecryptionError::IncorrectBlockSize(
                "block size has to have 16 bytes",
            ));
        }

        let array = GenericArray::from_mut_slice(block);
        self.cipher.decrypt_block(array);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_encryption_and_decryption() {
        let aes = AES::new();
        let mut block = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut expected = [
            101, 159, 42, 191, 197, 188, 7, 8, 251, 150, 231, 164, 74, 249, 213, 149,
        ];
        let block_copy = block.clone();
        aes.encrypt(&mut block);
        assert_eq!(block, expected);

        aes.decrypt(&mut block);
        assert_eq!(block, block_copy);
    }

    #[test]
    fn test_incorrect_encryption() {
        let aes = AES::new();

        let mut block = [42u8; 5];
        let err = aes.encrypt(&mut block).unwrap_err().to_string();

        assert_eq!(
            err,
            "block size has incorrect length: (block size has to have 16 bytes)"
        );
    }

    #[test]
    fn test_incorrect_decryption() {
        let aes = AES::new();

        let mut block = [42u8; 5];
        let err = aes.decrypt(&mut block).unwrap_err().to_string();

        assert_eq!(
            err,
            "block size has incorrect length: (block size has to have 16 bytes)"
        );
    }
}
