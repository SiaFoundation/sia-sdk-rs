---
sia_core_derive: minor
---

# Add `cross_target_test` attribute macro

Adds a `#[cross_target_test]` proc-macro attribute that emits the appropriate
test runner per target: `#[tokio::test]` on native and `#[wasm_bindgen_test]`
on `wasm32`, with the body wrapped in a `tokio::task::LocalSet` on `wasm32`
so tests can use `tokio::task::spawn_local`. Async fns get the tokio variant;
sync fns get the built-in `#[test]`.
