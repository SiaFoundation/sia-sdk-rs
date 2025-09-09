import asyncio
from indexd_ffi import App, Logger, set_log_callback

class PrintLogger(Logger):
    def debug(self, msg: "str"):
        print(f"[DEBUG] {msg}")
    def info(self, msg: "str"):
        print(f"[INFO] {msg}")
    def warn(self, msg: "str"):
        print(f"[WARN] {msg}")
    def error(self, msg: "str"):
        print(f"[ERROR] {msg}")

async def main():
    set_log_callback(PrintLogger())
    app = App("https://app.indexd.zeus.sia.dev", "test_app", b'\x01' * 32, "Test app")
    await app.connect()
    print("Connected to indexd")

    upload = await app.upload(b'\x01' * 32, 1, 2)
    print("starting chunked upload")
    await upload.write(b'\x02' * 1024)
    print("Wrote 1024 bytes")

    slabs = await upload.finish()
    print("Upload finished")
    for slab in slabs:
        print("Slab ID:", slab.id)

    download = await app.download(slabs)
    while True:
        chunk = await download.read(512)
        print("Read chunk of size:", len(chunk))
        if chunk == b'':
            break
    print("Download finished")

asyncio.run(main())