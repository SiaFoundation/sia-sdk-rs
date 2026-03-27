use std::fmt;
use std::future::Future;
use std::time::Duration;

/// WASM-compatible async sleep using `setTimeout`.
///
/// `tokio::time::sleep` requires the `time` feature which is not available
/// on WASM. This uses `setTimeout` via `js_sys` instead.
pub async fn sleep(duration: Duration) {
    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
        let global = js_sys::global();
        let set_timeout: js_sys::Function = js_sys::Reflect::get(&global, &"setTimeout".into())
            .unwrap()
            .into();
        let _ = set_timeout.call2(
            &wasm_bindgen::JsValue::NULL,
            &resolve,
            &wasm_bindgen::JsValue::from_f64(duration.as_millis() as f64),
        );
    }))
    .await
    .unwrap();
}

/// Error returned when a [`timeout`] expires.
#[derive(Debug)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "deadline has elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// WASM-compatible timeout. Races the given future against a [`sleep`] timer.
/// Returns `Err(Elapsed)` if the deadline expires first.
pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
    tokio::select! {
        result = future => Ok(result),
        _ = sleep(duration) => Err(Elapsed),
    }
}
