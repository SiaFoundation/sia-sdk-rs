import asyncio
import json
from datetime import datetime, timedelta, timezone
from logging import fatal
from os import urandom
from random import randint
from sys import stdin

from sia_storage_ffi import (
    AppMeta,
    Builder,
    DownloadOptions,
    Logger,
    Reader,
    UploadOptions,
    generate_recovery_phrase,
    set_logger,
    uniffi_set_event_loop,
)


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


set_logger(PrintLogger(), "debug")


async def main():
    uniffi_set_event_loop(asyncio.get_running_loop())  # type: ignore[arg-type]
    app_id = b"\x01" * 32

    builder = Builder("https://sia.storage", AppMeta(
        id=app_id,
        name="python example",
        description="an example app",
        service_url="https://example.com",
        logo_url=None,
        callback_url=None,
    ))

    await builder.request_connection()

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
    upload = await sdk.upload_packed(UploadOptions())

    i = 0
    data = None
    while upload.slabs() < 4:
        data = urandom(randint(1024, 1024 * 1024))
        reader = BytesReader(data)
        add_start = datetime.now(timezone.utc)
        size = await upload.add(reader)
        elapsed = datetime.now(timezone.utc) - add_start
        print(
            f"upload {i} added {size} bytes ({upload.length()} bytes, {upload.remaining()} remaining, {upload.slabs()} slab) in {elapsed}"
        )
        i += 1

    objects = await upload.finalize()
    elapsed = datetime.now(timezone.utc) - start
    print(f"Upload finished {len(objects)} objects in {elapsed}")

    start = datetime.now(timezone.utc)
    print(f"Downloading object {objects[-1].id()} {objects[-1].size()} bytes")
    reader = sdk.download(objects[-1], DownloadOptions())
    read_data = b""
    while (chunk := await reader.read()) != b"":
        read_data += chunk
    if read_data != data:
        print("Downloaded data does not match uploaded data")
    elapsed = datetime.now(timezone.utc) - start
    print(
        f"Downloaded object {objects[-1].id()} with {len(read_data)} bytes in {elapsed}"
    )


asyncio.run(main())
