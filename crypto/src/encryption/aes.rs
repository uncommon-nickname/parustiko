use super::errors::{DencryptionError, EncryptionError};
use super::Encryption;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
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

impl Encryption for AES {
    fn encrypt(&self, block: &mut [u8]) -> Result<(), EncryptionError> {
        let array: &mut [u8; 16] = block
            .try_into()
            .map_err(|_| EncryptionError::IncorrectBlockSize("block size has to have 16 bytes"))?;

        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(array));

        Ok(())
    }

    fn decrypt(&self, block: &mut [u8]) -> Result<(), DencryptionError> {
        let array: &mut [u8; 16] = block
            .try_into()
            .map_err(|_| DencryptionError::IncorrectBlockSize("block size has to have 16 bytes"))?;

        let array = GenericArray::from_mut_slice(array);
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

        let mut block = [42u8; 16];
        let copy_block = block.clone();
        aes.encrypt(&mut block);
        aes.decrypt(&mut block);
        assert_eq!(copy_block, block);
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
