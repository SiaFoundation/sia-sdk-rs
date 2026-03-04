---
sia_sdk_derive: minor
indexd: minor
indexd_ffi: minor
sia_sdk: minor
---

# mux 3: add Go interop tests, CI, and rpc_settings example

#279 by @Alrighttt

Adds cross-language tests (Rust client/Go server and vice versa) using a Go echo helper binary, CI steps to build the Go helper, and an example demonstrating RPCSettings over a mux connection.

The example can be run via `cargo run -p mux --example rpc_settings -- 127.0.0.1:9984 ed25519:4351516175d035523a5c047c70be882106a795966343b2ba60bb58d586b07d3b`

The Go binary must be built for tests to pass. The binary can be built via: `cd mux/testutil/go-interop && go build -o interop .`. This step has been added to the main github workflow to ensure.
