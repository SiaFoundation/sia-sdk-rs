---
sia_sdk: patch
sia_sdk_derive: patch
---

# Use chrono where possible

#145 by @chris124567

```
$ diff indexd/src/app_client.rs indexd_wasm/src/app_client.rs | wc -l
0
```

If we are going to copy paste code for different targets, then it makes sense for there to be as few differences between them as possible so that changes in one can be ported over easily to the other.
