import asyncio
import json
from sys import stdin
from indexd_ffi import generate_recovery_phrase, AppKey, AppConnectOptions, UnauthenticatedSdk, UploadOptions, DownloadOptions, set_logger, Logger
from logging import fatal
from datetime import datetime, timedelta, timezone

class PrintLogger(Logger):
    def debug(self, msg):
        print("DEBUG", msg)

    def info(self, msg):
        print("INFO", msg)

    def warning(self, msg):
        print("WARNING", msg)

    def error(self, msg):
        print("ERROR", msg)

set_logger(PrintLogger(), "debug")
async def main():
    print("Enter mnemonic (or leave empty to generate new):")
    mnemonic = stdin.readline().strip()
    if not mnemonic:
        mnemonic = generate_recovery_phrase()

    print("mnemonic:", mnemonic)
    app_id = b'\x01' * 32
    app_key = AppKey(mnemonic, app_id)
    sdk_auth = UnauthenticatedSdk(AppConnectOptions(
        indexer_url="https://app.sia.storage",
        name="python example",
        description= "an example app",
        service_url= "https://example.com",
        logo_url=None,
        callback_url=None,
        app_key=app_key,
    ))
    if not await sdk_auth.authorized():
        print("App not connected")
        resp = await sdk_auth.request_app_connection()
        print(f"Please approve connection {resp.response_url}")
        connected = await sdk_auth.wait_for_authorization(resp)
        if not connected:
            fatal("user rejected connection")

    sdk = await sdk_auth.sdk()
    print("Connected to indexd")

    writer = await sdk.upload(UploadOptions(
        metadata=json.dumps({"example": "value"}).encode(),
    ))
    print("starting upload")
    wrote_data = b'hello, world!'
    await writer.write(wrote_data)
    print("Wrote", len(wrote_data), "bytes")
    obj = await writer.finalize()
    print("Upload finished", obj.size(), obj.metadata().decode())

    sealed = obj.seal(app_key)
    print("sealed:", sealed.id, sealed.signature)

    reader = await sdk.download(obj, DownloadOptions())
    read_data = b''
    while True:
        chunk = await reader.read_chunk()
        if not chunk:
            break
        read_data += chunk

    if wrote_data != read_data:
        print("data mismatch", wrote_data, read_data)

asyncio.run(main())
