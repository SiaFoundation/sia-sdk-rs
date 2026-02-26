---
indexd: minor
sia_sdk: minor
indexd_ffi: minor
sia_sdk_derive: minor
---

# Mux module init

#276 by @Alrighttt

Introduces the mux crate with the frame module: FrameHeader encode/decode, PacketReader, PacketWriter, and the PacketCipher trait for sequential AEAD encryption.

This is a small piece of a much larger pull request: https://github.com/SiaFoundation/sia-sdk-rs/pull/273 . 
