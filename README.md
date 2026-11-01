# sing-vmess

Some confusing protocol.

### Features

100% compatible with `v2ray-core`.

* Stream length chunk with padding and masking
* AEAD length chunk with padding
* Stream chunk
* AEAD chunk
* Legacy client
* AEAD client
* Legacy server
* AEAD server

Extra features:

* Mux server
* XUDP client
* VLESS client

## Herta-Network fork

This fork retains the `github.com/metacubex/sing-vmess` package identity and
pins the shared sing implementation to Herta-Network/sing. Consumers must repeat
the replacement in their main module because dependency replacements are not
inherited by Go.

UDP writes retain one cipher record per datagram rather than applying the TCP
15 KB chunk limiter. Cipher, nonce, length-mask and padding layers are unchanged.
The packet payload limit reserves the worst-case uint16 framing overhead.
Plaintext VMess UDP cannot encode an empty packet separately from a terminating
zero-length chunk and returns an explicit error. XUDP now delivers empty UDP
frames without changing empty TCP/control-frame behavior. Failed lazy response
headers release their payload buffers and reject short writes.

Local regressions cover 60 KB records across cipher modes, empty encrypted
packets, XUDP empty delivery, and response-header write failures. They are not
an interoperability claim for third-party production servers.
