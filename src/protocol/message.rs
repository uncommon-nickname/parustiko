use num_derive::FromPrimitive;

#[repr(u8)]
#[derive(Debug, Eq, FromPrimitive, PartialEq)]
pub enum SSHMessageID {
    KexInit = 20,
}
