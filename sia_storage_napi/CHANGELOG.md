## 0.6.1 (2026-04-23)

### Features

- `upload_packed` now returns a `Result` and will error if invalid options are passed to it.

### Fixes

#### Emit NAPI type definitions

Enable the `type-def` feature on `napi-derive` and add `ts_args_type` on `set_logger` so `napi build --dts` produces a usable `index.d.ts`.

## 0.6.0 (2026-04-18)

### Breaking Changes

- Initialize nodejs bindings
- Replaced upload/download progress channels with more detailed callbacks.

### Fixes

- Removed hardcoded 1s timeout for RPC settings when writing and reading sectors
