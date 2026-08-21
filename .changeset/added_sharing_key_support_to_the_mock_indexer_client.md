---
sia_storage: minor
---

# Added sharing key support to the mock indexer client.

The mock indexer now implements the sharing key endpoints in memory, and `MockNetwork::shared_sdk` builds a `SharedSdk` from a seed, so tests can drive the whole sharing flow without a network.
