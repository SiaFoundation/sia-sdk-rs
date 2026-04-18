mod app_key;
mod builder;
mod helpers;
mod object;
mod packed;
mod sdk;
mod sealed;
mod types;

use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;

thread_local! {
    static LOCAL_SET: std::cell::OnceCell<&'static tokio::task::LocalSet> = const { std::cell::OnceCell::new() };
}

/// Spawns a future onto the tokio LocalSet and returns its result.
/// The LocalSet runs in the background on the browser event loop,
/// so this does not block — the browser can still process fetch
/// responses and other async work while the future executes.
pub(crate) async fn run_local<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T> + 'static,
    T: 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    LOCAL_SET.with(|ls| {
        ls.get()
            .expect("tokio runtime not initialized — was init() called?")
            .spawn_local(async move {
                let _ = tx.send(f.await);
            });
    });
    rx.await.expect("run_local task was dropped")
}

/// Set up panic hook, logger, and tokio runtime for browser use.
/// Defaults to Info level. Call `set_log_level("debug")` for verbose output.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Trace).ok();
    log::set_max_level(log::LevelFilter::Info);

    // Create a single-threaded tokio runtime + LocalSet. The runtime
    // context is entered so tokio primitives work. The LocalSet runs
    // forever on the browser event loop via wasm_bindgen_futures::spawn_local,
    // driving all tasks spawned with tokio::task::spawn_local.
    let rt = Box::leak(Box::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime"),
    ));
    let local_set: &'static _ = Box::leak(Box::new(tokio::task::LocalSet::new()));
    std::mem::forget(rt.enter());
    // Enter the LocalSet context so tokio::task::spawn_local (used by
    // the core SDK via maybe_spawn!) works from any sync or async context.
    std::mem::forget(local_set.enter());
    LOCAL_SET.with(|ls| ls.set(local_set).ok());
    // Run the LocalSet forever on the browser event loop so spawned
    // tasks are actually polled.
    wasm_bindgen_futures::spawn_local(local_set.run_until(std::future::pending::<()>()));
}

/// Sets the global log level filter at runtime.
///
/// Accepts `"debug"`, `"info"`, `"warn"`, or `"error"`. Unrecognized
/// values default to `"info"`. The change takes effect immediately for
/// all subsequent `log::debug!()` / `log::info!()` / etc. calls.
///
/// ```js
/// set_log_level("debug"); // verbose — shows RPC calls, slab progress, etc.
/// set_log_level("error"); // quiet — only fatal errors
/// ```
#[wasm_bindgen(js_name = "setLogLevel")]
pub fn set_log_level(level: &str) {
    let filter = match level {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    log::set_max_level(filter);
}

/// Generates a new BIP-39 12-word recovery phrase.
#[wasm_bindgen(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> String {
    sia_storage::generate_recovery_phrase()
}

/// Validates a BIP-39 recovery phrase.
#[wasm_bindgen(js_name = "validateRecoveryPhrase")]
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), JsError> {
    sia_storage::validate_recovery_phrase(phrase).map_err(to_js_err)
}

/// Calculates the encoded size of data after erasure coding.
#[wasm_bindgen(js_name = "encodedSize")]
pub fn encoded_size(data_size: f64, data_shards: u8, parity_shards: u8) -> f64 {
    sia_storage::encoded_size(data_size as u64, data_shards, parity_shards) as f64
}
