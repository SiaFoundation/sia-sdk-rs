---
indexd: patch
---

# Fix upload racing race conditon

#258 by @Alrighttt

This fixes a race condition in the upload logic that could happen when the amount of healthy hosts is nearly the same as the amount of shards. This could happen when the racing mechanism was triggered prior to all of the initial shards being assigned a host. The slow hosts would be consumed from the HostQueue without completing the upload. This would cause a latter shard to hit a QueueError::NoMoreHosts error.

This changes the upload behavior so that each shard has a host assigned before any upload begins.

A `set_slow_hosts` method was added to the `MockRHP4Client` to allow easily testing these conditions. This mimics a similar mechanism from the Go SDK.

This additionally addresses https://github.com/SiaFoundation/sia-sdk-rs/issues/251 because it was such a minor change. 
