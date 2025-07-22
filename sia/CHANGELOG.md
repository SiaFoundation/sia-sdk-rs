## 0.0.2 (2025-07-21)

### Features

- Add JSON serialization to ChainState
- Add ID derivation helpers to transactions, blocks, and siafund claims
- v2 signing implemented

#### Refactor V1 transaction signing

Replaced `v1::Transaction::sign` with `v1::Transaction::whole_sig_hash` and `v1::Transaction::partial_sig_hash`. This change is primarily to provide a more consistent experience with `core` and the V2::Transaction API.

### Fixes

- Fix element accumulator encoding
