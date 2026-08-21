---
sia_storage: minor
---

# Added sharing keys for scoped, read-only access to objects.

A sharing key grants read-only access to a chosen set of objects without the recipient needing an account, an app registration, or an approval flow. Owners create a key with `Sdk::create_sharing_key`, attach objects with `SharingKey::add_object`, and hand out the key's seed; recipients connect with `SharedSdk::connect`, which pays for reads from the owner's account rather than their own.
