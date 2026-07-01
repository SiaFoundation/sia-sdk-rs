---
sia_storage: patch
---

# Reject malformed share-link encryption keys.

The error for a bad share-link key now states it must be base64url-encoded rather than hex (the fragment was already decoded as base64url), and a fragment that does not decode to exactly 32 bytes is rejected instead of being silently zero-padded into a bogus key.
