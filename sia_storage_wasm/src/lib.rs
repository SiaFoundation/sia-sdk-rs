mod app_key;
mod builder;
mod helpers;
mod object;
mod packed;
mod sdk;
mod sealed;
mod streaming;
mod types;

use sia_storage;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;

/// Set up panic hook and logger for browser console output.
/// Defaults to Info level. Call `set_log_level("debug")` for verbose output.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Trace).ok();
    log::set_max_level(log::LevelFilter::Info);
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
#[wasm_bindgen]
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
#[wasm_bindgen]
pub fn generate_recovery_phrase() -> String {
    sia_storage::generate_recovery_phrase()
}

/// Validates a BIP-39 recovery phrase.
#[wasm_bindgen]
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), JsValue> {
    sia_storage::validate_recovery_phrase(phrase).map_err(to_js_err)
}

/// Calculates the encoded size of data after erasure coding.
#[wasm_bindgen]
pub fn calculate_encoded_size(data_size: u64, data_shards: u8, parity_shards: u8) -> u64 {
    sia_storage::encoded_size(data_size, data_shards, parity_shards)
}
