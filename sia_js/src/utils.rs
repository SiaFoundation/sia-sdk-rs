use js_sys::Array;
use wasm_bindgen::JsError;

pub(crate) fn vec_to_js_array<T: serde::Serialize>(vec: Vec<T>) -> Result<Array, JsError> {
    let arr = Array::new_with_length(vec.len() as u32);
    for (i, item) in vec.iter().enumerate() {
        let v = serde_wasm_bindgen::to_value(&item)?;
        arr.set(i as u32, v);
    }
    Ok(arr)
}
