import asyncio
from indexd_ffi import AppMeta, Sdk
from logging import fatal

async def main():
    sdk = Sdk("https://app.indexd.zeus.sia.dev", b'\x01' * 32)
    if not await sdk.connect():
        print("App not connected")
        resp = await sdk.request_app_connection(AppMeta(
            name="python example",
            description= "an example app",
            service_url= "https://example.com",
            logo_url=None,
            callback_url=None,
        ))
        connected = await sdk.wait_for_connect(resp)
        if not connected:
            fatal("user rejected connection")

    print("Connected to indexd")

    writer = await sdk.upload(b'\x01' * 32, 2, 6)
    print("starting upload")
    wrote_data = b'x02' * 1024
    await writer.write(wrote_data)
    print("Wrote 1024 bytes")
    slabs = await writer.finalize()
    print("Upload finished")

    reader = await sdk.download(slabs)
    read_data = await reader.read_chunk()
    if wrote_data != read_data:
        print("data mismatch", wrote_data, read_data)


asyncio.run(main())
