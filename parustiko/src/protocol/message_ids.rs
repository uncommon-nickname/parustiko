use num_derive::FromPrimitive;

#[repr(u8)]
#[derive(Debug, Eq, FromPrimitive, PartialEq, Clone)]
pub enum SshMessageID {
    KexInit = 20,
}
