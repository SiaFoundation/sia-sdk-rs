import asyncio
from indexd_ffi import generate_recovery_phrase, AppKey, AppMeta, Sdk, UploadOptions, DownloadOptions, set_logger, Logger
from logging import fatal

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
    mnemonic = generate_recovery_phrase()
    print("mnemonic:", mnemonic)
    app_id = b'\x01' * 32
    app_key = AppKey(mnemonic, app_id)
    sdk = Sdk("https://app.sia.storage", app_key)
    if not await sdk.connect():
        print("App not connected")
        resp = await sdk.request_app_connection(AppMeta(
            name="python example",
            description= "an example app",
            service_url= "https://example.com",
            logo_url=None,
            callback_url=None,
        ))
        print(f"Please approve connection {resp.response_url}")
        connected = await sdk.wait_for_connect(resp)
        if not connected:
            fatal("user rejected connection")

    print("Connected to indexd")

    writer = await sdk.upload(UploadOptions(
        max_inflight=15,
        data_shards=1,
        parity_shards=3,
        progress_callback=None
    ))
    print("starting upload")
    wrote_data = b'x02' * 1024
    await writer.write(wrote_data)
    print("Wrote 1024 bytes")
    obj = await writer.finalize()
    print("Upload finished")

    sealed = obj.seal(app_key)
    print("sealed:", sealed)

    reader = await sdk.download(obj, DownloadOptions(
        max_inflight=15,
        offset=0,
        length=None,
    ))
    read_data = await reader.read_chunk()
    if wrote_data != read_data:
        print("data mismatch", wrote_data, read_data)


asyncio.run(main())
