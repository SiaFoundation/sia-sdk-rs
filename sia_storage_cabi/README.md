# sia_storage_cabi

The C ABI that [`go.sia.tech/siastorage`][go-bindings] is built on. It exists
so the Go bindings can reach the storage engine through cgo without
reimplementing any of it: erasure coding, encryption, host selection and the
RHP4 transport stay here, in Rust.

**C is not a supported language.** The surface is shaped for the Go bindings
and changes with them, so treat it as their private interface rather than a
public one. Anything else linking it is on its own.

`include/sia_storage.h` is the contract. It is hand maintained rather than
generated, and a test asserts it declares exactly what the crate exports, in
both directions: a declaration with no export fails the Go build at link
time, and an export with no declaration is one the bindings cannot reach.

[go-bindings]: https://github.com/SiaFoundation/sia-storage-go

## Building

```bash
cargo build -p sia_storage_cabi --release
```

That produces the `staticlib` cgo links, and nothing else. It carries about
4 MB of the standard library's own debug info, which `-C strip=debuginfo`
does not remove from a staticlib, so a strip step buys nothing.

The crate is `publish = false`, so there is no crates.io release to depend on.
Depend on the Go bindings instead.

Consumers should not build their own archive for distribution. An archive
compiled on a developer machine cannot be traced back to a revision or
reproduced by anyone else, so the Go bindings build theirs in CI and record
the source revision alongside it.

## Conventions

These hold across the whole surface, and the header repeats them at the top.

**Fallible functions return a status code.** `SIA_OK` is success. On failure
they set `*err` to a heap-allocated message, which the caller frees with
`sia_string_free`.

**Handles are opaque pointers the caller owns**, released with the matching
`*_free`. There is one per type that outlives a call.

**A null handle is reported, not dereferenced.** A fallible function returns
`SIA_ERR_INVALID_HANDLE` without setting `*err`; a getter returns a zero value;
a void function does nothing; a `*_free` accepts null, as `free(3)` does. This
catches an absent handle, not a dangling one, and a non-null handle must still
be live. Out parameters are not checked and are written only on success.

**Blocking calls take an optional `sia_cancel_t`.** Passing `NULL` makes a call
uncancellable; otherwise cancelling the token unblocks it with
`SIA_ERR_CANCELLED`.

**Timestamps are Unix microseconds, UTC.**

**Constness says whether a handle can be shared between threads.** Every handle
moves between threads freely. A call taking a `const` handle may run alongside
other `const` calls on the same one; a call taking a non-const handle needs
exclusive use of it. `sia_cancel_cancel` is `const` for that reason, since
cancelling from another thread is how you unblock a call. A compile time
assertion in the crate holds the underlying Rust types to
this, so the guarantee cannot quietly lapse.

**Optional scalars are a `has_` flag beside the value**, as in
`sia_upload_options_t`. `Option<u64>` is not FFI safe, having no niche, so
there is no way to express it directly.

## Surface

The entry points, grouped by the handle they act on.

| area | what it covers |
|---|---|
| `sia_builder_*` | connect to an indexer, walk the approval flow, register a key |
| `sia_sdk_*` | account, objects, events, pinning, hosts, slabs, sharing keys |
| `sia_object_*` | size, metadata, ids, truncation, the sealed JSON crossing |
| `sia_upload_*` / `sia_packed_upload_*` | streaming writes, and packing small objects into one slab |
| `sia_download_*` | streaming reads |
| `sia_shared_sdk_*` | the recipient side of a sharing key |
| `sia_sharing_key_*` | import, export and inspect a key |
| `sia_cancel_*`, `sia_string_free`, `sia_set_logger` | lifecycle and process wide bits |

A `sia_shared_sdk_t` authenticates with a sharing key rather than an app key,
so a process holding nothing but the 32 byte seed can list, fetch and download
what the key grants, with no account, registration or approval step. It is read
only.

Host listings (`sia_sdk_hosts`, `sia_shared_sdk_hosts`) and pinned slabs
(`sia_sdk_slab`) cross as JSON rather than as typed structs, because both carry
a variable length list a flat C struct cannot hold. The shapes match what the
indexer returns.

Those three, plus `sia_sdk_account` and the sealed object crossing
(`sia_object_seal_json`, `sia_object_from_sealed_json`), hand back or take a
string, which the Go side decodes with `encoding/json`. Everything else on the
surface is typed.

## The mock feature

`--features mock` adds an in-memory host transport alongside the real one, plus
the `sia_mock_*` entry points that build an SDK on it. Real erasure coding,
encryption and transfer pipelines run against it; only the network is faked.

It is for tests. A production archive must not export those symbols, and the Go
bindings assert as much before shipping one.

```bash
cargo test -p sia_storage_cabi --features mock
```

## Panics

A function that takes an `err` out parameter catches panics and reports them as
`SIA_ERR`. The rest have nowhere to put a message, so they are written not to
panic; if one ever did, Rust aborts at the boundary rather than unwinding into
C, which would be undefined.
