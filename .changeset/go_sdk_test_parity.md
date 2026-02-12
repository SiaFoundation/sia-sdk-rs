---
indexd: patch
indexd_ffi: patch
sia_sdk: patch
sia_sdk_derive: patch
---

# Go SDK test parity

#266 by @Alrighttt

This pull requests adds some missing test cases that exist within the Go SDK. Closes https://github.com/SiaFoundation/sia-sdk-rs/issues/220

The remaining tests that have not been ported require changes to the `SDK` struct to allow mocking the `api_client`. I will work on a solution for this. 
