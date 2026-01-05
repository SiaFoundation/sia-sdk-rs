import asyncio
import json
from sys import stdin
from indexd_ffi import generate_recovery_phrase, AppMeta, Builder, UploadOptions, DownloadOptions, set_logger, Logger
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
    app_id = b'\x01' * 32
    
    builder = Builder("https://app.sia.storage")
    
    await builder.request_connection(AppMeta(
        id = app_id,
        name="python example",
        description= "an example app",
        service_url= "https://example.com",
        logo_url=None,
        callback_url=None,
    ))

    print(f"Please approve connection {builder.response_url()}")
    await builder.wait_for_approval()

    print("Enter mnemonic (or leave empty to generate new):")
    mnemonic = stdin.readline().strip()
    if not mnemonic:
        mnemonic = generate_recovery_phrase()
        print("mnemonic:", mnemonic)

    sdk = await builder.register(mnemonic)

    # Store the app key for later use
    app_key = sdk.app_key()
    print("App registered", app_key.export())

    print("Connected to indexd")

    start = datetime.now(timezone.utc)
    writer = await sdk.upload(UploadOptions(
        metadata=json.dumps({"example": "value"}).encode(),
    ))
    print("starting upload")
    wrote_data = b'hello, world!'
    await writer.write(wrote_data)
    print("Wrote", len(wrote_data), "bytes")
    obj = await writer.finalize()
    elapsed = datetime.now(timezone.utc) - start
    print(f"Upload finished {obj.size()} in {elapsed}")

    sealed = obj.seal(app_key)
    print("sealed:", sealed.id, sealed.data_signature)

    start = datetime.now(timezone.utc)
    reader = await sdk.download(obj, DownloadOptions())
    read_data = b''
    while True:
        chunk = await reader.read_chunk()
        if not chunk:
            break
        read_data += chunk

    if wrote_data != read_data:
        print("data mismatch", wrote_data, read_data)
    elapsed = datetime.now(timezone.utc) - start
    print(f"Download finished {len(read_data)} bytes in {elapsed}")

asyncio.run(main())
