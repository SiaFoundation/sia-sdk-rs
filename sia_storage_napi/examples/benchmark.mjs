import { Builder, PinnedObject, setLogger } from "./index.js";
import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";

const APP_META = {
  id: Buffer.from(
    "5c0b1af28e6ac76395b2087ea987297b9c496f90d2ab3e3d3d07980ae4c43633",
    "hex",
  ),
  name: "My Example App",
  description: "My Example App Description",
  serviceUrl: "https://myexampleapp.com",
};

function prompt(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) =>
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    }),
  );
}

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Number(bytes);
  for (const unit of units) {
    if (value < 1024 || unit === units[units.length - 1]) {
      return `${value.toFixed(2)} ${unit}`;
    }
    value /= 1024;
  }
}

function formatBitrate(bytes, durationMs) {
  const bitsPerSec = (Number(bytes) * 8) / (durationMs / 1000);
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let value = bitsPerSec;
  for (const unit of units) {
    if (value < 1000 || unit === units[units.length - 1]) {
      return `${value.toFixed(2)} ${unit}`;
    }
    value /= 1000;
  }
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      size: { type: "string", short: "s", default: String(120 * 1024 * 1024) },
      loglevel: { type: "string", short: "l", default: "warn" },
    },
  });
  const size = parseInt(values.size, 10);

  setLogger((msg) => console.log(msg), values.loglevel);

  // Authorize the app to access the user's storage.
  const builder = new Builder("https://sia.storage", APP_META);

  await builder.requestConnection();
  console.log(
    `Visit the following URL to authorize the application: ${builder.responseUrl()}`,
  );

  await builder.waitForApproval();
  console.log("Connection approved!");

  const phrase = await prompt("Enter recovery phrase: ");

  const sdk = await builder.register(phrase);
  console.log("App registered successfully!");

  // Generate random data to upload.
  const data = randomBytes(size);

  // Upload the data.
  console.log(`Uploading ${formatBytes(size)} of random data...`);
  const uploadStart = performance.now();
  const obj = await sdk.upload(new PinnedObject(), new Blob([data]).stream(), {});
  const uploadMs = performance.now() - uploadStart;

  // Pin the object.
  await sdk.pinObject(obj);
  console.log("Object pinned successfully!");

  // Download and verify.
  console.log("Downloading object...");
  let verified = 0;
  let ttfb = null;
  let maxGap = 0;
  let lastChunkTime = null;

  const downloadStart = performance.now();
  const dlStream = sdk.download(obj, {});
  for await (const chunk of dlStream) {
    const now = performance.now();
    if (ttfb === null) {
      ttfb = now - downloadStart;
    }
    if (lastChunkTime !== null) {
      const gap = now - lastChunkTime;
      if (gap > maxGap) maxGap = gap;
    }
    lastChunkTime = now;

    // Verify chunk matches original data.
    const chunkBuf = Buffer.from(chunk);
    const expected = data.subarray(verified, verified + chunkBuf.length);
    if (verified + chunkBuf.length > size) {
      throw new Error(`received more data than expected`);
    }
    if (!chunkBuf.equals(expected)) {
      throw new Error(`data mismatch at byte ${verified}`);
    }
    verified += chunkBuf.length;
  }
  const downloadMs = performance.now() - downloadStart;

  if (verified !== size) {
    throw new Error(`expected ${size - verified} more bytes`);
  }

  const objSize = Number(obj.size());
  const objEncoded = Number(obj.encodedSize());

  console.log(
    `Object uploaded ID: ${obj.id()}\tSize: ${formatBytes(objSize)}\tEncoded: ${formatBytes(objEncoded)}\tElapsed: ${formatDuration(uploadMs)}\tThroughput: ${formatBitrate(objSize, uploadMs)}\tEncoded Throughput: ${formatBitrate(objEncoded, uploadMs)}`,
  );
  console.log(
    `Object downloaded ID: ${obj.id()}\tSize: ${formatBytes(objSize)}\tEncoded: ${formatBytes(objEncoded)}\tElapsed: ${formatDuration(downloadMs)}\tTTFB: ${formatDuration(ttfb ?? 0)}\tThroughput: ${formatBitrate(objSize, downloadMs)}\tMax Write Latency: ${formatDuration(maxGap)}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});