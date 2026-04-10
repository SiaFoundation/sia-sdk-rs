# sia_storage_wasm — PR Checklist

## Doc fixes
- [ ] `SdkBuilder.register` doc says "StorageSdk" — should say "Sdk"
- [ ] `Upload` class doc says "A streaming upload handle" — should say "An upload handle"
- [ ] `Sdk` class doc comment may be truncated in .d.ts — verify

## Cleanup
- [ ] Check if `serde-wasm-bindgen` is still needed in Cargo.toml
- [ ] Commit `sia_storage/src/download.rs` fix (max_inflight back to 80)
- [ ] Add `example/` to git
- [ ] Remove or commit `sia_storage_wasm/src/TODO.md` (old notes)
- [ ] Rebuild `example/pkg/` with latest WASM

## Future work (not blocking PR)
- [ ] `knownHosts()` — return public keys of all loaded hosts
- [ ] `hostAccountInfo(hostKey)` — balance and prices for a specific host
- [ ] Avoid `.clone()` in `PinnedObject.open()` if core SDK adds `&SealedObject` support
