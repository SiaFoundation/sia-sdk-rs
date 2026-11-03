# Go consensus goldens

Generates `sia_core/testdata/consensus.json.gz` from Go core. The file is checked in; CI fails if it is stale.

Regenerate after changing the generator or `go.mod`:

```sh
cd sia_core/testutil/consensus-goldens && go run .
```

| Group | Checks |
| --- | --- |
| `networks` | Mainnet and Zen parameters, JSON encoding |
| `v1` | Transaction and output IDs, whole and partial sig hashes, unlock-condition addresses |
| `v2` | Transaction ID, input sig hash, contract/renewal/attestation sig hashes, child IDs, contract tax |
| `policies` | Spend-policy addresses, satisfied-policy encoding |
| `ids` | Block, siafund, contract, and transaction child IDs |
| `rhp4` | Price and token hashes, challenge hashes, wire encodings |
