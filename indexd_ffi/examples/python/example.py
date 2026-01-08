import asyncio
import json
from sys import stdin
from indexd_ffi import uniffi_set_event_loop, generate_recovery_phrase, AppMeta, Builder, Reader, Write, UploadOptions, DownloadOptions, set_logger, Logger
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

from io import BytesIO

class BytesReader(Reader):
    def __init__(self, data: bytes, chunk_size: int = 65536):
        self.buffer = BytesIO(data)
        self.chunk_size = chunk_size

    async def read(self) -> bytes:
        return self.buffer.read(self.chunk_size)


class BytesWriter(Write):
    def __init__(self):
        self.buffer = BytesIO()

    async def write(self, data: bytes) -> None:
        if len(data) > 0:
            self.buffer.write(data)

    def get_data(self) -> bytes:
        return self.buffer.getvalue()

set_logger(PrintLogger(), "debug")
async def main():
    uniffi_set_event_loop(asyncio.get_running_loop()) # type: ignore[arg-type]
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
    data = b'hello, world!'
    reader = BytesReader(data)
    print("starting upload")
    object = await sdk.upload(reader, UploadOptions())
    elapsed = datetime.now(timezone.utc) - start
    print(f"Upload finished {object.size()} in {elapsed}")
    await sdk.pin_object(object)
    
    print("pinned", object.id())

    start = datetime.now(timezone.utc)
    writer = BytesWriter()
    await sdk.download(writer, object, DownloadOptions())
    elapsed = datetime.now(timezone.utc) - start
    
    if writer.get_data() != data:
        print("data mismatch", data, writer.get_data())

    print(f"Download finished {len(writer.get_data())} bytes in {elapsed}")

asyncio.run(main())
