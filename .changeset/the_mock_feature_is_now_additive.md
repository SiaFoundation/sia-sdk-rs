---
sia_storage: major
---

# The `mock` feature is now additive.

Enabling `mock` previously replaced the siamux backend. Both the Sia transport and indexer backend are now selected at construction time through an enum, so the mock ones are added alongside the real ones and a single build can drive either.

`MockUploader`, `MockDownloader`, and `MockHosts` are removed. They existed only because the mock transport could not be combined with an indexer client, and each was a duplicate of the equivalent `Sdk` method. Use `MockNetwork::sdk` and call `Sdk::upload`, `Sdk::upload_packed`, and `Sdk::download` instead.
