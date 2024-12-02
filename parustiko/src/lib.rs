mod errors;
mod protocol;
mod version_exchange;

use crypto::encryption::aes::{GenericArray, AES};
use crypto::encryption::Encryption;
use errors::VersionExchangeError;
use protocol::DecodeRaw;
use protocol::{BinaryProtocolPacket, Decode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use version_exchange::{KeyExchange, SshVersion};

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("10.10.10.10:22")?;
    stream.set_read_timeout(Some(Duration::from_millis(10)))?;
    let _ = stream.set_nonblocking(true);

    let mut buffer = [0; 128];

    let client_version = SshVersion::try_build("2.0", "parustiko0.0.1", None)?;

    stream.write_all(client_version.to_string().as_bytes())?;
    std::thread::sleep(Duration::from_millis(10));

    let header = SshVersion::read_header(&mut stream)?;
    let server_version =
        SshVersion::from_string(String::from_utf8(header)?.trim_matches(char::from(0)))?;

    let mut bpp = <BinaryProtocolPacket as DecodeRaw>::from_be_bytes(&mut stream, 0)?;
    let key_exchange = KeyExchange::from_bytes(&mut bpp.get_payload())?;

    Ok(())
}
