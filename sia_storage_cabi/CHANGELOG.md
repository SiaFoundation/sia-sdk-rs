## 0.1.1 (2026-10-21)

### Features

- Added a C ABI for the storage SDK.

### Fixes

#### Upgrade reqwest and update TLS security dependencies

Upgrade reqwest to 0.13.5, using platform certificate verification on native platforms except Android. Android uses a preconfigured Rustls client with bundled roots to avoid requiring JNI initialization. Browser builds continue using browser TLS.

Update `webpki-roots` to 1.0.10 and `rustls-webpki` to 0.103.16 in the lockfile to address RUSTSEC-2026-0381 and RUSTSEC-2026-0382.
