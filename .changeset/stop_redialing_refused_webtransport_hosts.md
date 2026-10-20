---
sia_storage: patch
sia_storage_wasm: patch
---

# Stop redialing hosts that refused a WebTransport handshake

Chrome counts every failed WebTransport handshake against the whole browser for five minutes, and while any are counted it delays each new connection by 10 ms doubled per failure, up to a minute. The browser client dialed a host again on the next read after its handshake failed, so a few unreachable hosts kept adding failures, and within minutes dials to healthy hosts took 35 to 60 seconds. An address that refuses a handshake is now not dialed again for five minutes, and a host whose addresses have all refused fails at once with `DialRefused`, so the download moves to other hosts. A dial that only times out is not counted, since Chrome can hold a healthy host back for up to a minute while it is counting failures.
