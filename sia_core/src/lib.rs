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
