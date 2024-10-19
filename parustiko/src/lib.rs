mod errors;
mod protocol;

use crypto::encryption::aes::{GenericArray, AES};
use crypto::encryption::Encryption;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("10.10.10.10:22")?;
    stream.set_read_timeout(Some(Duration::from_millis(10)))?;

    let mut buffer = [0; 128];
    loop {
        let bytes = match stream.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if bytes == 0 {
            break;
        }

        let text = std::str::from_utf8(&buffer[..bytes])?;
        println!("recv: {}", text);
    }

    // Required part: SSH-2.0-{...}[, extra info]\r\n
    let client_version =
        String::from("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4, OpenSSL 3.0.13 30 Jan 2024\r\n");

    stream.write_all(client_version.as_bytes())?;
    let mut output = Vec::new();
    loop {
        let bytes = match stream.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => 0,
        };
        if bytes == 0 {
            break;
        }

        output.extend_from_slice(&buffer[..bytes]);
    }
    println!("{:?}", String::from_utf8_lossy(&Cow::Borrowed(&output)));

    Ok(())
}
