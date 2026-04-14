import {
  Builder,
  generateRecoveryPhrase,
  setLogger,
} from './index.js';
import { strict as assert } from 'node:assert';
import { createInterface } from 'node:readline';

const INDEXER_URL = process.env.INDEXER_URL || 'https://sia.storage';

function prompt(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer.trim());
  }));
}

function randomBytes(n) {
  const buf = Buffer.alloc(n);
  for (let off = 0; off < n; off += 65536) {
    const len = Math.min(65536, n - off);
    crypto.getRandomValues(buf.subarray(off, off + len));
  }
  return buf;
}

async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

setLogger((msg) => console.log(msg), 'debug');

async function main() {
  const appId = new Uint8Array(32).fill(0x01);
  const builder = new Builder(INDEXER_URL, {
    id: appId,
    name: 'napi example',
    description: 'an example app',
    serviceUrl: 'https://example.com',
  });

  await builder.requestConnection();
  console.log(`Please approve connection: ${builder.responseUrl()}`);
  await builder.waitForApproval();

  let mnemonic = await prompt('Enter mnemonic (or leave empty to generate new): ');
  if (!mnemonic) {
    mnemonic = generateRecoveryPhrase();
    console.log('mnemonic:', mnemonic);
  }

  const sdk = await builder.register(mnemonic);
  const appKey = sdk.appKey();
  console.log('App registered', appKey.publicKey());

  // packed upload
  const start = performance.now();
  const upload = await sdk.uploadPacked({});

  let i = 0;
  let lastData = null;
  while (upload.slabs() < 4n) {
    const size = Math.floor(Math.random() * (1024 * 1024 - 1024)) + 1024;
    lastData = randomBytes(size);
    const stream = new Blob([lastData]).stream();
    const addStart = performance.now();
    const added = await upload.add(stream);
    const elapsed = ((performance.now() - addStart) / 1000).toFixed(2);
    console.log(
      `upload ${i} added ${added} bytes (${upload.length()} total, ${upload.remaining()} remaining, ${upload.slabs()} slabs) in ${elapsed}s`
    );
    i++;
  }

  const objects = await upload.finalize();
  const uploadElapsed = ((performance.now() - start) / 1000).toFixed(2);
  console.log(`Upload finished ${objects.length} objects in ${uploadElapsed}s`);

  // download last object
  const lastObj = objects[objects.length - 1];
  console.log(`Downloading object ${lastObj.id()} ${lastObj.size()} bytes`);
  const dlStart = performance.now();
  const dlStream = sdk.download(lastObj, {});
  const downloaded = await readAll(dlStream);
  const dlElapsed = ((performance.now() - dlStart) / 1000).toFixed(2);

  assert.ok(downloaded.equals(lastData), 'Downloaded data does not match uploaded data');
  console.log(`Downloaded ${downloaded.length} bytes in ${dlElapsed}s`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
