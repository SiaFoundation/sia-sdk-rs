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
mod mock;
mod object;
mod sdk;
mod sharing;
mod upload;

#[cfg(all(test, feature = "mock"))]
mod tests;
