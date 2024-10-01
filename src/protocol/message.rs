use num_derive::FromPrimitive;

#[repr(u8)]
#[derive(FromPrimitive)]
pub enum SSHMessageID {
    Kexinit = 20,
}
