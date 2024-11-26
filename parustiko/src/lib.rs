mod errors;
mod preamble;
mod protocol;

use crypto::encryption::aes::{GenericArray, AES};
use crypto::encryption::Encryption;
use preamble::version_exchange::errors::VersionExchangeError;
use preamble::version_exchange::{KeyExchange, SshVersion};
use protocol::bpp::BinaryProtocolPacket;
use protocol::DecodeRaw;
use std::borrow::Cow;
use std::fs::read;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// Read bytes from stream until CR and LF ('\r\n') occur
fn read_header<T: Read>(arr: &mut T) -> Result<Vec<u8>, VersionExchangeError> {
    let mut header = Vec::with_capacity(51);
    let mut prev_byte = None;

    loop {
        let mut byte = [0u8; 1];

        arr.read_exact(&mut byte)
            .map_err(|e| VersionExchangeError::EmptyStream("Unexpected end of stream"))?;

        header.push(byte[0]);

        if let Some(13) = prev_byte {
            if byte[0] == 10 {
                break;
            }
        }
        prev_byte = Some(byte[0]);
    }
    Ok(header)
}

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("10.10.10.10:22")?;
    stream.set_read_timeout(Some(Duration::from_millis(10)))?;
    let _ = stream.set_nonblocking(true);

    let mut buffer = [0; 128];

    let client_version = SshVersion::try_build("2.0", "parustiko0.0.1", None)?;

    stream.write_all(client_version.to_string().as_bytes())?;
    std::thread::sleep(Duration::from_millis(10));

    let header = read_header(&mut stream)?;
    let server_version =
        SshVersion::from_string(String::from_utf8_lossy(&header).trim_matches(char::from(0)))?;

    let mut bpp = BinaryProtocolPacket::from_be_bytes(&mut stream, 0)?;

    let key_exchange = KeyExchange::from_bytes(&mut bpp.payload);
    println!(">>>> {:#?}", key_exchange);

    Ok(())
}
