mod errors;
mod preamble;
mod protocol;

use crypto::encryption::aes::{GenericArray, AES};
use crypto::encryption::Encryption;
use protocol::bpp::BinaryProtocolPacket;
use protocol::DecodeRaw;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn runner() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("10.10.10.10:22")?;
    stream.set_read_timeout(Some(Duration::from_millis(10)))?;
    stream.set_nonblocking(true);

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
    let client_version = String::from("SSH-2.0-parustiko0.0.1\r\n");

    stream.write_all(client_version.as_bytes())?;
    std::thread::sleep(Duration::from_millis(10));

    let mut dupa = [0; 41]; //ignore SSH...
    stream.read(&mut dupa)?;
    let b = BinaryProtocolPacket::from_be_bytes(&mut stream, 0); // TODO!change
    println!("{:?}", b);
    // // this message is part of KEX
    // let mut output = Vec::new();
    // loop {
    //     let bytes = match stream.read(&mut buffer) {
    //         Ok(n) => n,
    //         Err(_) => 0,
    //     };
    //     if bytes == 0 {
    //         break;
    //     }

    //     output.extend_from_slice(&buffer[..bytes]);
    // }

    // println!("{:?}", String::from_utf8_lossy(&Cow::Borrowed(&output)));

    Ok(())
}


"""
>>> bytes(l)
b'\x14\x03N\xca#)\x9e\xfb&$3\xc6\xf9\x88[C\xf9\x00\x00\x01\x02curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1\x00\x00\x00Assh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> len("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n")
41
>>> l=[20, 212, 116, 246, 155, 120, 7, 156, 61, 142, 213, 28, 6, 90, 146, 24, 168, 0, 0, 1, 2, 99, 117, 114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 44, 99, 117, 114, 118, 101, 50, 53, 53, 49, 57, 45, 115, 104, 97, 50, 53, 54, 64, 108, 105, 98, 115, 115, 104, 46, 111, 114, 103, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 44, 101, 99, 100, 104, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 45, 101, 120, 99, 104, 97, 110, 103, 101, 45, 115, 104, 97, 50, 53, 54, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 54, 45, 115, 104, 97, 53, 49, 50, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 56, 45, 115, 104, 97, 53, 49, 50, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 52, 45, 115, 104, 97, 50, 53, 54, 44, 100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45, 103, 114, 111, 117, 112, 49, 52, 45, 115, 104, 97, 49, 0, 0, 0, 65, 115, 115, 104, 45, 114, 115, 97, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 114, 115, 97, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 44, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 108, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 49, 50, 56, 45, 99, 116, 114, 44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44, 97, 101, 115, 50, 53, 54, 45, 99, 116, 114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 50, 53, 54, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 108, 99, 104, 97, 99, 104, 97, 50, 48, 45, 112, 111, 108, 121, 49, 51, 48, 53, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 49, 50, 56, 45, 99, 116, 114, 44, 97, 101, 115, 49, 57, 50, 45, 99, 116, 114, 44, 97, 101, 115, 50, 53, 54, 45, 99, 116, 114, 44, 97, 101, 115, 49, 50, 56, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 97, 101, 115, 50, 53, 54, 45, 103, 99, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 213, 117, 109, 97, 99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 0, 0, 0, 213, 117, 109, 97, 99, 45, 54, 52, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 45, 101, 116, 109, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 54, 52, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 117, 109, 97, 99, 45, 49, 50, 56, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 50, 53, 54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 50, 45, 53, 49, 50, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 0, 0, 0, 21, 110, 111, 110, 101, 44, 122, 108, 105, 98, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 21, 110, 111, 110, 101, 44, 122, 108, 105, 98, 64, 111, 112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
>>> bytes(l)
b'\x14\xd4t\xf6\x9bx\x07\x9c=\x8e\xd5\x1c\x06Z\x92\x18\xa8\x00\x00\x01\x02curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1\x00\x00\x00Assh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> bytes(l)[17:]
b'\x00\x00\x01\x02curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1\x00\x00\x00Assh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> bytes(l)[21:21+258]
b'curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1'
>>> bytes(l)[21+258:21+258+4]
b'\x00\x00\x00A'
>>> int.from_bytes(_,byteorder="big")
65
>>> len("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n")
"""