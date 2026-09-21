//! C interface to the `sia_storage` crate, consumed by the Go SDK via cgo.
//!
//! See `include/sia_storage.h` for the C-side contract.
//!
//! A function that takes an `err` out parameter catches panics and reports
//! them as `SIA_ERR`. The rest have nowhere to put a message, so they are
//! written not to panic. If one ever did, Rust aborts at the boundary rather
//! than unwinding into C.

mod abi;
mod builder;
mod download;
// Gated here rather than on each item inside. With the module always
// compiled, every mock entry point needed its own attribute, and forgetting
// one on a new function would ship mock code in a production archive.
#[cfg(feature = "mock")]
mod mock;
mod object;
mod sdk;
mod sharing;
mod upload;

#[cfg(all(test, feature = "mock"))]
mod tests;
