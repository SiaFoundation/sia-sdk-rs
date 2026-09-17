# Repository review instructions

## Source of truth

Treat the public API in `sia_storage` as the source of truth for SDK behavior.

The bindings in `sia_storage_ffi`, `sia_storage_napi`, and `sia_storage_wasm`
adapt that API for their target languages and runtimes. Do not infer the
intended core API from an existing binding.

## Binding parity

When a pull request changes a public API in `sia_storage` or any binding:

- Inspect the corresponding implementation in the core SDK and every applicable
  binding.
- Compare methods, parameters, return values, defaults, optionality, ownership
  requirements, synchronous versus asynchronous behavior, and exposed data
  fields.
- Flag core methods or fields missing from an applicable binding.
- Flag binding behavior that requires more or different semantic information
  than the core API.
- Flag inconsistent behavior between bindings unless the difference is an
  established platform adaptation.
- Check both `Sdk` and related types such as `SharedSdk`, `PinnedObject`,
  `PackedUpload`, option records, query records, builders, and key types.

For example, if a core method accepts an object ID, a binding may encode that ID
as a string or byte array, but it should not require a complete `PinnedObject`.

## Representation adaptations

Compare APIs by semantic input and output, not by identical language-level
types.

Allow idiomatic representation differences such as:

- Rust IDs and public keys represented as validated strings.
- Fixed-size byte arrays represented as `Vec<u8>`, `Buffer`, `Uint8Array`, or
  an explicitly documented hex or base64 string.
- Rust timestamps represented using the target language's date type.
- Rust integers represented using an appropriate native number or bigint type.
- Platform-specific streams and callbacks.
- Native filesystem path APIs that are unavailable in browsers.
- WASM restricting host operations to QUIC because browsers cannot use SiaMux.

When representations differ, verify that conversions consistently validate:

- Encodings and malformed input.
- Fixed byte lengths.
- Integer signs, ranges, overflow, and precision.
- Required and optional values.
- Date and timestamp validity.

## API shape

Flag accidental differences in:

- Method and property names, including generated casing.
- IDs versus full objects.
- Required versus optional parameters.
- Default values and behavior when arguments are omitted.
- Pagination and query support.
- Synchronous versus asynchronous methods.
- Error behavior.
- Mutable versus immutable operations.
- Constructors, factory methods, getters, and return wrappers.

A platform-specific type representation is acceptable. A change in the meaning,
capability, or information required by an operation is not.

## Generated bindings

Do not rely only on the Rust signatures compiling.

For binding changes, inspect or generate the public declarations when practical:

- TypeScript declarations for `sia_storage_napi`.
- TypeScript declarations produced by `sia_storage_wasm`.
- At least one generated UniFFI language binding for `sia_storage_ffi`.

Verify that generated declarations preserve the intended names, argument types,
optional parameters, return types, and synchronous or asynchronous behavior.

## Review expectations

When reporting a parity problem:

- Identify the core SDK method or type that defines the contract.
- Identify every affected binding.
- Explain whether the difference is semantic or representational.
- Recommend aligning the bindings with the core SDK unless a documented
  platform constraint requires an adaptation.