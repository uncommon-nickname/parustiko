# Initial SSH Connection

SSH works over any 8-bit clean, binary-transparent transport, protecting agains Tx errors. When used over TCP/IP, the server normally listens for connections on port 22.

## Protocol Version Exchange

The first step in SSH initialization after the TCP/IP connection is alive, is for both entities to exchange the supported protocol versions using the identification string:

```
SSH-protoversion-softwareversion SP comments CR LF
```

- `protoversion`: 1.x or 2.0 respectively,
- `softwareversion`: differs (for OpenSSH it is `OpenSSH_7.4`),
- `SP`: a space character (ASCII 32),
- `comments`: optional additional data,
- `CR`: single carriage return char (ASCII 13),
- `LF`: single line feed char (ASCII 10).

Some old versions of undocumented SSH may not use the `CR`. Maximum length of the string is 255 characters. Both `protoversion` and `softwareversion` must consist of printable US-ASCII characters with the exception of whitespace characters and the minus sign. For example:

```
SSH-2.0-billsSSH_3.6q3<CR><LF>
```

![protocol-version-exchange](./images/protocol-version-exchange.png)

## Binary Packet Protocol

Each packet exchanged after the protocol version exchange is done, should be of a following format:

- `uint32_t` packet_length,
- `uint8_t` padding_length,
- `uint8_t[n1]` payload (n1 = packet_length - padding_length - 1),
- `uint8_t[n2]` random padding (n2 = padding_length),
- `uint8_t[m]` mac (m = mac_length),

packet_length: The length of the packet in bytes, not including `mac` or the `packet_length` field itself,

padding_length: The length of `random_padding` in bytes,

payload: The useful contents of the packet. If compression has been negotiated, this field is compressed. Initially the compression must be `none`.

random_padding: Arbitrary-length padding, such that the total length of (packet_length + padding_length + payload + random_padding) is a multiple of the cipher block size or 8, whichever is larger. There must be at least four bytes of padding. The padding should consist of random bytes. The maximum amount of padding is 255 bytes.

mac: Message Authentication Code. If message authentication has been negotiated, this field contains the MAC bytes. Initially the MAC algorithm must be `none`.

#### Packet size

All impmentations must be able to process packets with an uncompressed payload length of `32768` bytes or less and a total packet size of `35000` bytes or less. Implementations should support longer packets, where they might be needed.

#### Compression

If compression is negotiated, the `payload` field (and only it) will be compressed using the negotiated algorithm. The `packet_length` field and `mac` will be computed from the compressed payload.

## Protocol Key Exchange (KEX)

![protocol-key-exchange](./images/protocol-key-exchange.png)
