import asyncio
from sys import stdin
from datetime import datetime, timezone
from io import BytesIO

from sia_indexd import (
    uniffi_set_event_loop,
    generate_recovery_phrase,
    AppMeta,
    Builder,
    UploadOptions,
    DownloadOptions,
    set_logger,
    Logger,
    # Wrappers for standard Python file-like objects
    BytesReader,
    BytesWriter,
    # Convenience functions for simple upload/download
    upload_bytes,
    download_bytes,
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


set_logger(PrintLogger(), "debug")


async def main():
    uniffi_set_event_loop(asyncio.get_running_loop())  # type: ignore[arg-type]
    app_id = b"\x01" * 32

    builder = Builder("https://app.sia.storage")

    await builder.request_connection(
        AppMeta(
            id=app_id,
            name="python example",
            description="an example app",
            service_url="https://example.com",
            logo_url=None,
            callback_url=None,
        )
    )

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

    for i in range(10):
        data = f"hello, world {i}!"
        reader = BytesReader(BytesIO(data.encode()))
        size = await upload.add(reader)
        rem = await upload.remaining()
        print(f"upload {i} added {size} bytes ({rem} remaining)")

    objects = await upload.finalize()
    elapsed = datetime.now(timezone.utc) - start
    print(f"Upload finished {len(objects)} objects in {elapsed}")

    start = datetime.now(timezone.utc)
    writer = BytesWriter(BytesIO())
    print(f"Downloading object {objects[-1].id()} {objects[-1].size()} bytes")
    await sdk.download(writer, objects[-1], DownloadOptions())
    elapsed = datetime.now(timezone.utc) - start
    print(
        f"Downloaded object {objects[-1].id()} with {len(writer._stream.getvalue())} bytes in {elapsed}"
    )

    # Convenience functions for simple cases
    print("\nConvenience function examples...")

    obj = await upload_bytes(sdk, b"hello from upload_bytes!")
    print(f"Uploaded {obj.size()} bytes with upload_bytes()")

    data = await download_bytes(sdk, obj)
    print(f"Downloaded with download_bytes(): {data.decode()!r}")


asyncio.run(main())
