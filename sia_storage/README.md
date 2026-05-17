# sia_storage

A Rust SDK for storing and retrieving data on the [Sia](https://sia.tech) decentralized storage network.

Sia is a decentralized cloud storage platform where data is stored across a global network of independent hosts. Storage contracts are enforced by the Sia blockchain, so no single party controls your data. Compared to centralized providers, Sia offers lower costs, stronger privacy (data is client-side encrypted by default), and censorship resistance.

This crate provides a high-level interface for interacting with Sia through an indexer service. Data is automatically erasure-coded, encrypted, and distributed across hosts.

## Usage

### Connecting for the first time

Use `Builder` to start the approval flow with an indexer. The user must approve the connection through the indexer's UI, after which an `AppKey` is derived from their recovery phrase.

```rust
use sia_storage::{Builder, AppMetadata, app_id};

const APP_META: AppMetadata = AppMetadata {
    id: app_id!("a9f0bda1b97b7d44ae6369ac830851a115311bb59aa2d848beda6ae95d10ad18"),
    name: "My App",
    description: "My App Description",
    service_url: "https://myapp.com",
    logo_url: Some("https://myapp.com/logo.png"),
    callback_url: None,
};

let builder = Builder::new("https://sia.storage", APP_META)?;
let builder = builder.request_connection().await?;

// Display builder.response_url() to the user for approval
let builder = builder.wait_for_approval().await?;
let sdk = builder.register("twelve word recovery phrase goes here ...").await?;

// Save the app key for future connections
let exported = sdk.app_key().export();
```

### Reconnecting with an existing key

```rust
use sia_storage::{Builder, AppKey};

let app_key = AppKey::import(saved_key);
let builder = Builder::new("https://sia.storage", APP_META)?;
if let Some(sdk) = builder.connected(&app_key).await? {
    // Connected successfully
}
```

### Uploading and downloading

```rust
use sia_storage::{Object, UploadOptions, DownloadOptions};

// Upload
let object = sdk.upload(Object::default(), reader, UploadOptions::default()).await?;
sdk.pin_object(&object).await?;

// Download
let mut reader = sdk.download(&object, DownloadOptions::default())?;
tokio::io::copy(&mut reader, &mut writer).await?;
```

## Key management

The `AppKey` grants full access to a user's data. After connecting, retrieve it with `SDK::app_key()`, then persist it using `AppKey::export()` and restore it with `AppKey::import()` so users don't need to re-approve on every launch.

## Building for WebAssembly

For best performance in the browser, enable the `simd128` target feature:

```bash
RUSTFLAGS="-C target-feature=+simd128" \
  cargo build --target wasm32-unknown-unknown --release
```

The same `RUSTFLAGS` applies to `wasm-pack build`. SIMD-enabled WASM is supported by all modern browsers; no special hosting headers are required.

## License

This project is licensed under the MIT License.
