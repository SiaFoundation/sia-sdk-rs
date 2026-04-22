---
default: minor
---

# Uploads will no longer block indefinitely until completion.

Removed the progressive upload timeout and hosts are now retried a maximum of 3 times before giving up. The default 
timeout is now 1.5m per shard per attempt. This should give enough time on slow connections. Racing and prioritization
will still prioritize faster hosts after warming up.

Users can still manually timeout 