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

/// Unified task utilities for native and WASM targets.
pub mod task {
    /// A wrapper around [`tokio::task::JoinHandle`] that aborts the task
    /// when dropped. Replaces `tokio_util::task::AbortOnDropHandle` with
    /// a cross-platform implementation that works on both native and WASM.
    pub struct AbortOnDropHandle<T>(tokio::task::JoinHandle<T>);

    impl<T> Drop for AbortOnDropHandle<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    impl<T> AbortOnDropHandle<T> {
        pub fn new(handle: tokio::task::JoinHandle<T>) -> Self {
            Self(handle)
        }
    }

    impl<T> std::ops::Deref for AbortOnDropHandle<T> {
        type Target = tokio::task::JoinHandle<T>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T> std::future::Future for AbortOnDropHandle<T> {
        type Output = Result<T, tokio::task::JoinError>;

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::pin::Pin::new(&mut self.0).poll(cx)
        }
    }
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

/// Spawn a future on a [`tokio::task::JoinSet`]. Uses `spawn` on native
/// (requires `Send`) and `spawn_local` on WASM (no `Send` required).
///
/// ```ignore
/// let mut set = tokio::task::JoinSet::new();
/// join_set_spawn!(set, async move { do_work().await });
/// ```
macro_rules! join_set_spawn {
    ($set:expr, $fut:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        $set.spawn($fut);
        #[cfg(target_arch = "wasm32")]
        $set.spawn_local($fut);
    }};
}

/// Spawn a future as a standalone task. Uses `tokio::spawn` on native
/// (requires `Send`) and `tokio::task::spawn_local` on WASM.
///
/// ```ignore
/// let handle = maybe_spawn!(async move { do_work().await });
/// ```
macro_rules! maybe_spawn {
    ($fut:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::spawn($fut)
        }
        #[cfg(target_arch = "wasm32")]
        {
            tokio::task::spawn_local($fut)
        }
    }};
}

/// Dual-target test macro. All test functions must be `async fn`.
/// Uses `#[tokio::test]` on native and `#[wasm_bindgen_test]` on WASM.
///
/// Can only be invoked once per scope (module) because it emits a
/// `use wasm_bindgen_test::*;` import.
#[cfg(test)]
macro_rules! cross_target_tests {
    ($($test_fn:item)*) => {
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::*;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_test_configure!(run_in_browser);

        $(
            #[cfg(target_arch = "wasm32")]
            #[wasm_bindgen_test]
            $test_fn

            #[cfg(not(target_arch = "wasm32"))]
            #[tokio::test]
            $test_fn
        )*
    };
}

/// Run an async block inside a `tokio::task::LocalSet` on WASM, or directly
/// on native. Assumes a tokio runtime is already active (e.g. inside
/// `#[tokio::main]`, `#[tokio::test]`, or after `Runtime::enter()`).
#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) async fn run_local<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(f).await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) async fn run_local<F: std::future::Future>(f: F) -> F::Output {
    f.await
}
