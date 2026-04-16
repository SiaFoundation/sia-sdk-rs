---
sia_storage: major
sia_storage_ffi: major
---

# Download returns an AsyncRead

`SDK::download` now returns a `Download` handle implementing `AsyncRead`
instead of taking a writer. Callers pull data with `tokio::io::copy` or any
other `AsyncRead` consumer.

The `sia_storage_ffi` `SDK::download` now returns a `Download` object with
`read()` and `close()` methods instead of taking a foreign `Writer`. The
`Writer` foreign trait has been removed.
