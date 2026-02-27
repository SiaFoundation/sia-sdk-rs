---
indexd_ffi: patch
sia_sdk_derive: patch
indexd: patch
sia_sdk: patch
---

# fix decrypt race condition

#274 by @Alrighttt

Fix a bug in `CipherWriter::poll_write` where the XChaCha20 keystream advances before the inner writer confirms it accepted the data, causing silent data corruption on download.

Discovered this while using sialo:
`sialo download -o HTML/homepage.html 'sia://app.sia.storage/objects/a7653b7c62bf0653f1c0ec025ee2857f1d8eb52cb29498b23693e434de73692a/shared?sv=2376599154&sc=nmS95u9mPXfFkjj8fkVfCw28mgyVgq9IQOUQYBykQNs%3D&ss=Jd7rlRzhEspDkp7Tn0ADdCs3yoyi5tCo5PBdkOQyBjcuyJ6OrifL7OXSnF5Dob2yUCTW6QGVV_2NFCW3d_yRAA%3D%3D#encryption_key=__jJLf9TDtrcZx7XlS1o32YK2n4RqaXa6xANJXjRkd4='`

This object in particular results in decryption failing without this fix. 
