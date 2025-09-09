import asyncio
from indexd import App, Logger, set_log_callback

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

    upload = await app.upload(b'\x01' * 32, 2, 6)
    print("starting chunked upload")
    await upload.write(b'\x02' * 1024)
    print("Wrote 1024 bytes")
    await upload.finish()
    print("Upload finished")


asyncio.run(main())