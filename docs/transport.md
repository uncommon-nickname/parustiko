# Transport Layer Protocol

Transport protocol providing strong encryption, cryptographic authentication and integrity protection.

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

Both `protoversion` and `softwareversion` must consist of printable US-ASCII characters with the exception of whitespace characters and the minus sign. For example:

```
SSH-2.0-billsSSH_3.6q3<CR><LF>
```

![protocol-version-exchange](./images/protocol-version-exchange.png)

## Binary Packet Protocol

Each packet exchanged after the protocol version exchange is done, should be of a following format:

- `uint32_t` packet_length
- `uint8_t` padding_length
- `uint8_t[n1]` payload (n1 = packet_length - padding_length - 1)
- `uint8_t[n2]` random padding (n2 = padding_length)
- `uint8_t[m]` mac (m = mac_length)

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

Key exchange begins by each side sending name-lists of supported algorithms. Each side has a preferred algorithm in each category. Each side may guess which algorithm the other side is using and may send an initial key exchange packet according to the algorithm. If the guess is wrong, then the proper algorithm negotiation is performed and the initial packet should be discarded.

If the guess was right, the optimistically sent packet must be handled as the first key exchange packet.

A key exchange method uses explicit server authentication if the key exchange messages include a signature or other proof of the server's authenticity.

#### Algorithm Negotiation

Key exchange beginds by sending the following packet:

- `uint8_t` SSH_MSG_KEXINIT
- `uint8_t[16]` cookie
- `name-list` kex_algorithms
- `name-list` server_host_key_algorithms
- `name-list` encryption_algorithms_client_to_server
- `name-list` encryption_algorithms_server_to_client
- `name-list` mac_algorithms_client_to_server
- `name-list` mac_algorithms_server_to_client
- `name-list` compression_algorithms_client_to_server
- `name-list` compression_algorithms_server_to_client
- `name-list` languages_client_to_server
- `name-list` languages_server_to_client
- `bool` first_kex_packet_follows
- `uint32_t` 0 (reserved for future use)

Note, that if the first algorithm in the `name-list` (called the preferred algorithm) is the same for client and the server it MUST be used. If the optimistic approach is supported, the `first_kex_packet_follows` boolean has to be set to TRUE!

![protocol-key-exchange](./images/protocol-key-exchange.png)

A key re-exchange during the session should also be supported. It can be initiated at any time by one of the parties and should be performed in exactly the same way. Note, that if key re-exchange is initialized, the encryption methods used to perform it should stay the same as in the communication before. It is recommended to re-exchange keys for every gigabyte of transmitted data, or one gour of connection time (whichever comes sooner).

#### Key Exchange Outcome

The key exchange produces two values: a shared secret `K`, and an exchange hash `H`. Encryption and authentication keys are derived from these. The exchange hash from the first key exchange is additionally used as the session identifier, which is a unique identifier for this connection. It does not change even if keys are re-exchanged later. Those values can be used to acquire initial `IV's`, encryption keys and integrity keys.
