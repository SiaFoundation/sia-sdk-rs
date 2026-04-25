# Sia storage crates — data-loss audit

## Scope

This audit looks for bugs in the Sia storage crates that could cause **data
loss** (silently or otherwise) — i.e. bytes that the caller successfully
uploads but cannot later retrieve as the same bytes. Crates audited:

- `sia_storage` — the upload/download/erasure-coding/encryption pipeline
- `sia_storage_ffi`, `sia_storage_napi`, `sia_storage_wasm` — bindings
- `sia_core/src/rhp4` — the host RPC / Merkle-proof layer it depends on

## TL;DR

I did not find a bug that silently corrupts uploaded bytes. The on-the-wire
guarantees are strong:

- Reed-Solomon (`reed_solomon_erasure::galois_8`) gives `min_of_total`
  redundancy with parameters validated to ≥99.99% recovery probability.
- `RPCWriteSector::complete` recomputes the sector Merkle root locally and
  rejects any host response whose root disagrees
  (`sia_core/src/rhp4/protocol.rs:710-715`).
- `RPCReadSector::complete` validates the host's range proof against the
  stored sector root before returning bytes
  (`sia_core/src/rhp4/protocol.rs:797-809`).
- Slab data is XChaCha20-encrypted per shard with a fresh 256-bit key per
  slab (`upload.rs:253`), so a hostile host cannot tamper undetectably.
- Reed-Solomon is applied to plaintext shards, then each shard is encrypted
  independently — this commutes correctly: decrypt-then-reconstruct yields
  the original plaintext (verified in `download.rs:267-273` and the existing
  `test_slab_recovery`).
- Object `id` (`slabs.rs:409-420`) is content-addressed, so a tampered
  metadata blob will not open under the user's `AppKey`.

What I did find is a set of **foot guns and non-atomic operations** that can
cause the user to *think* they have stored data when they have not. These
are ranked below.

---

## Findings, by severity

### 1. Volatile in-memory metadata between `upload()` and `pin_object()` *(highest-impact foot gun)*

**Severity:** High — easy way to lose data in practice.
**Bug?** Not strictly. By design, but undocumented as a hazard.
**Location:** `sia_storage/src/sdk.rs:165-203`, `sia_storage/src/upload.rs:350-368`,
`sia_storage/src/sdk.rs:341-362`.

After `Sdk::upload(...).await`, the caller holds an `Object` whose
`encryption_key`s and `Sector{root, host_key}` lists exist **only in process
memory**. The data has been written to hosts and is paid for, but no
durable record links the user to it. If the process exits or crashes before
`Sdk::pin_object` succeeds:

- The slab encryption keys are gone (random 256-bit per slab, generated at
  `upload.rs:253` and not persisted).
- The sector roots / host keys are gone.
- The bytes are still on hosts but unrecoverable for anyone — there is no
  index to find them by, no way to decrypt them, and the hosts will GC them
  in 432 blocks (`sia_core/src/rhp4/protocol.rs:641-642`).

**Why it bites users:** A naïve "upload then pin" flow is only safe if the
caller never crashes between the two awaits. Long-running uploads (large
files, slow networks) widen this window. The library exposes no
`upload_and_pin` atomic variant and no way to checkpoint partial upload
state.

**Evidence path:**
- `upload.rs:253` — `let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();`
  (only copy lives in the spawned slab task until `Upload::finish`).
- `upload.rs:357-365` — `Upload::finish` returns `Vec<Slab>` to the caller;
  no persistence step.
- `sdk.rs:165-179` — `Sdk::upload` returns `Result<Object, UploadError>`;
  the caller is expected (per docstring) to `pin_object` themselves.

**Suggested fix:** Either offer `Sdk::upload_and_pin` that pin-and-uploads
atomically (calling `pin_slabs` per slab as it completes, then
`pin_object`), or document loudly in the rustdoc that an unpinned `Object`
is volatile and that hosts will GC the bytes.

---

### 2. Two-phase `pin_object` is non-atomic (orphans slabs on partial failure)

**Severity:** Medium — wastes user storage quota; does not lose user data.
**Bug?** Yes (atomicity bug), but not data-loss.
**Location:** `sia_storage/src/sdk.rs:341-362`.

```rust
pub async fn pin_object(&self, object: &Object) -> Result<(), Error> {
    let slabs = object.slabs().iter().map(...).collect();
    self.api_client.pin_slabs(...).await.map_err(...)?;  // (A)
    self.api_client.pin_object(...).await.map_err(...)?; // (B)
    Ok(())
}
```

If (A) succeeds but (B) fails (network blip, indexer 5xx, app killed), the
slabs are pinned to the user's account — counted against quota — but
referenced by no `SealedObject`. They become orphans until the user calls
`Sdk::prune_slabs` (`sdk.rs:279-285`).

**Demonstration:**
- A user retries `pin_object`: that re-pins the same slabs and re-pins the
  object. If `pin_slabs` is idempotent on slab-id (it should be — the slab
  digest at `slabs.rs:51-60` is content-addressed), this is fine.
- A user does *not* retry: storage quota silently leaks.

**Suggested fix:** Reverse the dependency by having `pin_object` accept the
slab list inline so the indexer commits both in a single transaction; or
swallow the `pin_object` failure long enough to `prune_slabs` on the same
account.

---

### 3. Racing-host uploads leak orphaned sectors

**Severity:** Low — wastes host-side storage, does not lose data.
**Bug?** Behavioural, not a data-loss bug.
**Location:** `sia_storage/src/upload.rs:79-120`.

`ShardUpload::upload_shard` waits 1 second, then races a second host. The
loop returns `Ok(result)` as soon as **any** task succeeds (`upload.rs:89-98`).
When the original task is still in-flight at that moment, `JoinSet::drop`
aborts it — but if the network call has already been received and the host
has accepted the sector, the sector now exists on that host with a Merkle
root nobody references in slab metadata. The host will eventually GC it
(432 blocks), but until then the user pays for it.

This is dual to finding #2: the cost is host-side rather than indexer-side.

**Suggested fix:** After a winner is decided, send the loser a "free
sector" RPC (which already exists in `HostPrices::free_sector_price`) for
its computed root, instead of relying on host-side timeout GC.

---

### 4. `HostQueue::retry` not bounded across racers

**Severity:** Low — at worst, fewer retry opportunities than expected.
**Bug?** Yes, off-by-some.
**Location:** `sia_storage/src/hosts.rs:654-667`,
`sia_storage/src/upload.rs:64`, `upload.rs:95`.

When a racer and the original both fail, `inspect_err` calls
`hosts.retry(host_key)` from each. `add_failure` is also called on the
original at `upload.rs:95` even when the racer succeeded — a non-failed
upload contributes to the failure metric, demoting the host's priority for
no reason. Reciprocally, a racer that fails counts toward `MAX_RETRIES=3`
just like a primary failure.

This isn't data loss — at worst, a slab fails to upload because its retry
budget was burned by racers.

**Suggested fix:** Distinguish "host was racing and lost" from "host
failed RPC" in metric updates.

---

### 5. `encrypt_recovered_shards` `shard_start + i as u8` is an unchecked add

**Severity:** Low — currently dead code path; future-bug landmine.
**Bug?** Latent.
**Location:** `sia_storage/src/encryption.rs:81-107`.

```rust
shards.par_iter_mut().enumerate().for_each(|(i, shard)| {
    if let Some(shard) = shard {
        encrypt_shard(key, shard_start + i as u8, offset, shard.as_mut());
    }
});
```

Today every caller passes `shard_start = 0` (`download.rs:267-272`), so
`shard_start + i as u8` ranges 0..total_shards-1 ≤ 255. But the parameter
exists, the addition is unchecked u8, and `validate()` permits up to 256
total shards (`lib.rs:400`). A future caller passing `shard_start > 0` with
a slab that has > 256 - shard_start shards will:

- panic in debug builds, or
- silently wrap to a duplicate shard index in release builds.

A shard-index collision means the same XChaCha20 keystream is XOR'd into
two different shards within the same slab → a chosen-plaintext attacker
gains plaintext bits; for our purposes here, the more relevant outcome is
that decrypt produces wrong bytes, and Reed-Solomon "reconstructs" garbage
that passes Merkle-proof verification because it happened *before*
encryption.

**Suggested fix:** Tighten the type — `shard_start: usize` with the
addition done in `usize` and `as u8` only at the very end with a
`debug_assert!(combined < 256)` guard. Or eliminate the parameter, since no
caller uses a non-zero value.

---

### 6. `Slab::digest` is not domain-separated

**Severity:** Informational. Not exploitable today; cryptographic hygiene.
**Location:** `sia_storage/src/slabs.rs:51-60`.

```rust
pub fn digest(&self) -> Hash256 {
    let mut state = Blake2b256::new();
    (self.min_shards as u64).encode(&mut state).unwrap();
    self.encryption_key.encode(&mut state).unwrap();
    self.sectors.iter().for_each(|sector| {
        sector.root.encode(&mut state).unwrap();
    });
    state.finalize().into()
}
```

There is no domain prefix and no length prefix on the sectors list. If a
future change adds a field — or if `EncryptionKey`'s `SiaEncode` length
ever changes — collisions become possible because sectors and the key
share a single hash input space. Today this is safe because all fields
have fixed sizes and `min_shards` is at the front, but a domain tag
(`b"slab"`) would harden against future refactors.

---

## Things I checked and found correct

- **Reed-Solomon ↔ XChaCha20 commute:** Encryption is per-shard XOR with
  independent keystreams; parity is computed before encryption; on the
  read path, decrypt happens before reconstruction. Verified in
  `download.rs:267-273` and the test `test_slab_recovery`.
- **Per-shard nonce:** `encrypt_shard` uses `nonce[0] = index` and a fresh
  random `slab_key` per slab (`upload.rs:253`), so no nonce reuse occurs
  within or across slabs. `validate()` caps total shards at 256
  (`lib.rs:400`), so `shard_index as u8` never overflows.
- **Object cipher continuity across slab boundaries:** `Chacha20Cipher` in
  `encryption.rs:139-205` rotates nonce every `2^32 * 64` bytes
  (`MAX_BYTES_PER_NONCE`), and `Download::poll_read`/`read_chunk` apply
  decrypt sequentially in chunk-completion order so the cipher state stays
  consistent.
- **`PackedUpload::finalize` slab-boundary math:** I traced single-slab,
  spanning, exact-boundary, full-then-partial, and zero-byte-tail object
  sizings; every case sums correctly to `sum(slab.length) == object.size()`.
- **`ChunkIter` past-end behaviour:** `Download::new` (`download.rs:511-512`)
  clamps `remaining` to `available = object_size - offset`, preventing a
  `slabs[slab_idx]` panic when the caller passes `offset >= object_size`.
- **`write_data_shards` partial-stripe writes:** The `skip > SEGMENT_SIZE`
  branch looks suspicious (should arguably be `>=`), but the `length =
  n.min(SEGMENT_SIZE - skip)` clamp evaluates to `0` in the boundary case,
  so a zero-byte slice is written and the math stays correct. Not pretty
  but not buggy.
- **Append (`upload_object` resume):** The new reader is wrapped at
  `object.size()`, so the chacha20 keystream picks up where the previous
  upload left off; new slabs are fresh entries appended to `slabs`. Verified
  by `test_upload_append` plus a manual trace through partial-last-slab
  resumes.
- **Host-response integrity:** `RPCReadSector::complete` verifies the
  range proof against the stored sector root; `RPCWriteSector::complete`
  recomputes the local Merkle root and rejects host responses that
  disagree.

---

## What I did NOT audit

- Cryptographic implementations of XChaCha20, BLAKE2b, Reed-Solomon — I
  trusted those crates.
- The indexer service itself — the audit is bound to the SDK; the indexer
  could lose, reorder, or tamper with `SealedObject` blobs and the SDK
  would only notice via `verify_signatures` (`slabs.rs:205-226`), which
  *does* protect against tampering at least.
- The native `web_transport` Quinn / WebTransport plumbing for connection
  reuse pathologies under heavy concurrency (skimmed, not traced).

---

*Audited on the `claude/audit-sia-data-loss-T86dF` branch against the tip
at `b979bb3` ("Merge pull request #344 ..."). All 59 unit tests pass.*
