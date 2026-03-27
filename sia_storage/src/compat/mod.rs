//! Platform compatibility layer for native and WASM targets.
//!
//! Import time types via `crate::time::` and task types via `crate::task::`.
//! Do not import from `std::time`, `tokio::time`, `web_time`, or
//! `tokio_util::task` directly in other modules.

#[cfg(target_arch = "wasm32")]
mod wasm_time;

/// Unified time types for native and WASM targets.
pub mod time {
    pub use web_time::{Duration, Instant};

    #[cfg(not(target_arch = "wasm32"))]
    pub use tokio::time::{error::Elapsed, sleep, timeout};

    #[cfg(target_arch = "wasm32")]
    pub use super::wasm_time::{Elapsed, sleep, timeout};
}

// --- Macros ---
// These must be defined in a `#[macro_use]` module declared before the
// modules that use them.

/// Run a blocking computation on `spawn_blocking` on native, or inline on WASM.
/// Must be called from an async context. The expression must return a type that
/// implements `Send + 'static` on native.
///
/// ```ignore
/// let result = maybe_spawn_blocking!(expensive_computation())?;
/// ```
macro_rules! maybe_spawn_blocking {
    ($body:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::task::spawn_blocking(move || $body).await?
        }
        #[cfg(target_arch = "wasm32")]
        {
            $body
        }
    }};
}

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

use std::future::Future;
use std::pin::Pin;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
