---
sia_storage: patch
sia_mux: patch
---

# Fix clippy lints introduced by Rust 1.98.

Rust 1.98 extended `clippy::result_large_err` to `impl Future` return positions, added `clippy::chunks_exact_to_as_chunks`, and tightened unused import detection. These are lint fixes only, with no behavior changes.
