---
sia_sdk_derive: minor
sia_sdk: minor
indexd: minor
indexd_ffi: minor
---

# mux 1: use ring instead of chacha20poly1305 crate and optimize frame module

#283 by @Alrighttt

This PR adds the foundational frame and handshake layers. Changes were needed as the mux implementation was rewritten for better performance.

This replaces the `chacha20poly1305` crate with `ring`. 

Additionally, this has optimizations to the frame module that reduce the amount of copying compared to the previous mux implementation. 
