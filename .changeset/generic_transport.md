---
indexd_ffi: minor
sia_sdk_derive: minor
indexd: minor
sia_sdk: minor
---

# Generic transport

#275 by @Alrighttt

The SDK was hardcoded to the QUIC transport (quic::Client). This change makes it possible to add new transport implementations (e.g. siamux, WebTransport) by implementing the RHP4Client trait, without modifying the Downloader, Uploader, or SDK internals.

This is a prerequisite for siamux support and WebTransport support. 

Adds https://crates.io/crates/async-trait as a dependency.
