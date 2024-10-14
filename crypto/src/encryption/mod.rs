pub mod aes;
pub mod errors;

pub enum EncryptionType {
    AES(aes::AES),
}

pub trait Encryption {
    fn encrypt(&self, block: &mut [u8]) -> Result<(), errors::EncryptionError>;
    fn decrypt(&self, block: &mut [u8]) -> Result<(), errors::DencryptionError>;
}
