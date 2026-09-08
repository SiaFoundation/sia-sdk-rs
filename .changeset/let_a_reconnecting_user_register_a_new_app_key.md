---
sia_storage_napi: minor
sia_storage_wasm: minor
sia_core: minor
sia_core_derive: minor
sia_mux: minor
sia_storage_ffi: minor
sia_storage: minor
---

# Let a reconnecting user register a new app key

#444 by @chris124567

Instead of the reconnecting check from `register`:
```
-        if self.state.reconnecting && !self.client.check_app_authenticated(&private_key).await? {
-            return Err(BuilderError::WrongRecoveryPhrase);
-        }
```

We let apps decide for themselves with `matches_existing_app_key`
