/// Offload expensive computation to a rayon thread on native, run inline on WASM.
///
/// On native, the expression is moved into a `rayon::spawn` closure and the result
/// is sent back via a `tokio::sync::oneshot` channel. On WASM (single-threaded),
/// the expression is evaluated inline.
///
/// Must be called from an async context (the native path uses `.await`).
/// The expression must be `Send + 'static` on native (captured by `move` closure).
///
/// ```ignore
/// let root = maybe_rayon!(merkle::sector_root(data.as_ref()));
/// let result = maybe_rayon!(proof.verify(&root, start, end))?;
/// ```
macro_rules! maybe_rayon {
    ($body:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            rayon::spawn(move || {
                let _ = tx.send($body);
            });
            rx.await.unwrap()
        }
        #[cfg(target_arch = "wasm32")]
        {
            $body
        }
    }};
}

/// Dual-target test macro. All test functions must be `async fn`.
/// Uses `#[tokio::test]` on native and `#[wasm_bindgen_test]` on WASM.
/// Sync tests work fine as `async fn` without any `.await` calls.
///
/// Can only be invoked once per scope (module) because it emits a
/// `use wasm_bindgen_test::*;` import. Place all cross-target tests for a
/// module inside a single invocation.
///
/// ```ignore
/// cross_target_tests! {
///     async fn test_something() {
///         assert_eq!(1 + 1, 2);
///     }
/// }
/// ```
///
/// Run native tests: `cargo test -p sia_core`
/// Run WASM tests:   `RUSTFLAGS='--cfg=web_sys_unstable_apis' wasm-pack test --chrome sia_core`
#[macro_export]
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

/// Run an async block inside a `tokio::task::LocalSet` on WASM, or directly on native.
///
/// Code that uses `tokio::task::spawn_local` (via the `join_set_spawn!` macro)
/// requires a `LocalSet` context. On native, `#[tokio::test]` provides a runtime
/// that supports `spawn_local` when using `flavor = "current_thread"`. On WASM,
/// `wasm_bindgen_test` does not, so this helper creates one.
///
/// ```ignore
/// cross_target_tests! {
///     async fn test_with_spawn_local() {
///         run_local(async {
///             // code that uses join_set_spawn! / spawn_local
///         }).await;
///     }
/// }
/// ```
#[cfg(target_arch = "wasm32")]
pub async fn run_local<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(f).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn run_local<F: std::future::Future>(f: F) -> F::Output {
    f.await
}

pub mod blake2;
pub mod consensus;
pub mod encoding;
pub mod encoding_async;
pub mod seed;
pub mod signing;
pub mod types;

pub mod macros;
pub mod merkle;
pub mod rhp4;

extern crate self as sia_core;
