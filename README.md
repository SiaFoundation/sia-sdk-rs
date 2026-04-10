# Sia SDK for Rust

A collection of Rust crates for building applications on the [Sia](https://sia.tech) decentralized storage network.

Sia is a decentralized cloud storage platform where data is stored across a global network of independent hosts. Storage contracts are enforced by the Sia blockchain, so no single party controls your data. Compared to centralized providers, Sia offers lower costs, stronger privacy (data is client-side encrypted by default), and censorship resistance.

## Crates

| Crate | Description |
|-------|-------------|
| [`sia_core`](sia_core/) | Core Sia types: addresses, keys, transactions, encoding, and the RHP4 protocol. |
| [`sia_storage`](sia_storage/) | High-level SDK for uploading and downloading data through an indexer. |
| [`sia_storage_ffi`](sia_storage_ffi/) | UniFFI bindings for `sia_storage`, targeting Swift, Kotlin, and Python. |
| [`sia_storage_napi`](sia_storage_napi/) | Node.js bindings for `sia_storage` via N-API. |
| [`sia_mux`](sia_mux/) | Multiplexed stream transport used by the RHP4 protocol. |

## Status

This project is under active development. The API will have breaking changes until 1.0.

## License

Licensed under the MIT License.
