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
