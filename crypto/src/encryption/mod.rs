pub mod aes;

pub trait EncryptionInterface {
    fn encrypt(&self, block: &mut [u8]);
    fn decrypt(&self, block: &mut [u8]);
}
