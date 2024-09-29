use super::EncryptionInterface;
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

impl EncryptionInterface for AES {
    fn encrypt(&self, block: &mut [u8]) {
        let array = GenericArray::from_mut_slice(block);
        self.cipher.encrypt_block(array);
    }
    fn decrypt(&self, block: &mut [u8]) {
        let array = GenericArray::from_mut_slice(block);
        self.cipher.decrypt_block(array);
    }
}
