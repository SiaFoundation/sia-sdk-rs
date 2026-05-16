---
sia_core: major
---

# Use u64 for output and contract ID derive indices

Changed the index parameter on `TransactionID`, `BlockID`, and `FileContractID`
ID-derive methods from `usize` to `u64`: `siacoin_output_id`, `siafund_output_id`,
`file_contract_id`, `miner_output_id`, `v2_siacoin_output_id`, `v2_siafund_output_id`,
`v2_file_contract_id`, `v2_attestation_id`, `valid_output_id`, and `missed_output_id`.

The hash input was already serialized as a little-endian `u64`, so on-chain IDs
are unchanged. The previous signature silently truncated indices to 32 bits on
`wasm32` (where `usize == u32`).
