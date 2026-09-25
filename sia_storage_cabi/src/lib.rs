//! C interface to the `sia_storage` crate, consumed by the Go SDK via cgo.
//!
//! See `include/sia_storage.h` for the C-side contract.
//!
//! A function that takes an `err` out parameter catches panics and reports
//! them as `SIA_ERR`. The rest have nowhere to put a message, so they are
//! written not to panic. If one ever did, Rust aborts at the boundary rather
//! than unwinding into C.

// The header promises C callers that every handle can move between threads,
// and that a call taking a const handle can run alongside other const calls on
// it. That rests on the Rust auto traits, which are invisible from C and can
// be lost by adding one field. These pin the promise: a type that stops being
// Send, or a shared one that stops being Sync, breaks the build here rather
// than turning the header into a lie.
//
// Only the types with a const entry point need Sync, since those are the ones
// C can hold two references to. FfiUpload and FfiDownload have none: every
// call on them is non-const, so exclusive use is already the contract.
const _: () = {
    const fn moves_between_threads<T: Send>() {}
    const fn shared_across_threads<T: Sync>() {}

    moves_between_threads::<sia_storage::Sdk>();
    moves_between_threads::<sia_storage::SharedSdk>();
    moves_between_threads::<sia_storage::Object>();
    moves_between_threads::<sia_storage::SharingKey>();
    moves_between_threads::<upload::FfiUpload>();
    moves_between_threads::<download::FfiDownload>();
    moves_between_threads::<builder::FfiBuilder>();
    moves_between_threads::<upload::FfiPacked>();

    shared_across_threads::<sia_storage::Sdk>();
    shared_across_threads::<sia_storage::SharedSdk>();
    shared_across_threads::<sia_storage::Object>();
    shared_across_threads::<sia_storage::SharingKey>();
    shared_across_threads::<upload::FfiPacked>();
    shared_across_threads::<tokio_util::sync::CancellationToken>();
};

mod abi;
mod builder;
mod download;
mod hosts;
// Gated here rather than on each item inside. With the module always
// compiled, every mock entry point needed its own attribute, and forgetting
// one on a new function would ship mock code in a production archive.
#[cfg(feature = "mock")]
mod mock;
mod object;
mod sdk;
mod shared_sdk;
mod sharing;
mod upload;

#[cfg(all(test, feature = "mock"))]
mod tests;
