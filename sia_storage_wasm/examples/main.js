import init, {
  Builder,
  generateRecoveryPhrase,
  PinnedObject,
  setLogger,
  SharedSdk,
} from './pkg/sia_storage_wasm.js';

const INDEXER_URL = 'https://sia.storage';
const logEl = document.getElementById('log');

function log(...args) {
  const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : a).join(' ');
  logEl.textContent += msg + '\n';
  console.log(...args);
}

function randomBytes(n) {
  const buf = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) {
    crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, n)));
  }
  return buf;
}

function askUser(label) {
  const area = document.getElementById('input-area');
  const field = document.getElementById('input-field');
  const btn = document.getElementById('input-submit');
  document.getElementById('input-label').textContent = label;
  field.value = '';
  area.style.display = '';
  field.focus();
  return new Promise((resolve) => {
    function submit() {
      btn.removeEventListener('click', submit);
      field.removeEventListener('keydown', onKey);
      area.style.display = 'none';
      resolve(field.value.trim());
    }
    function onKey(e) { if (e.key === 'Enter') submit(); }
    btn.addEventListener('click', submit);
    field.addEventListener('keydown', onKey);
  });
}

async function main() {
  await init();
  setLogger((msg) => log('[wasm]', msg), 'debug');

  // -- builder flow --
  const builder = new Builder(INDEXER_URL, {
    appId: '01'.repeat(32),
    name: 'wasm example',
    description: 'an example app',
    serviceUrl: 'https://example.com',
  });

  await builder.requestConnection();
  log('Approve connection:', builder.responseUrl());
  await builder.waitForApproval();

  const mnemonic = await askUser('Enter mnemonic (or leave empty to generate new):');
  const phrase2 = mnemonic || generateRecoveryPhrase();
  if (!mnemonic) log('Generated mnemonic:', phrase2);

  const sdk = await builder.register(phrase2);
  log('Registered. Public key:', sdk.appKey().publicKey());

  // -- upload --
  const uploadSize = 1024 * 1024 * 4; // 4 MiB
  const uploadData = randomBytes(uploadSize);
  log(`\nUploading ${(uploadSize / 1024 / 1024).toFixed(1)} MiB of random data...`);

  const uploadStart = performance.now();
  const obj = await sdk.upload(new PinnedObject(), new Blob([uploadData]).stream(),  {
    onShardUploaded: (progress) => {
      log(progress);
    },
  });
  const uploadElapsed = (performance.now() - uploadStart) / 1000;
  const rawMiB = uploadSize / 1024 / 1024;
  const encodedMiB = obj.encodedSize() / 1024 / 1024;
  log(`Upload complete: ${obj.size()} bytes in ${uploadElapsed.toFixed(2)}s (raw: ${(rawMiB / uploadElapsed).toFixed(2)} MiB/s, encoded: ${(encodedMiB / uploadElapsed).toFixed(2)} MiB/s)`);
  await sdk.pinObject(obj);
  log('Pinned object:', obj.id());

  // -- download --
  log(`\nDownloading object ${obj.id()} (${obj.size()} bytes)...`);
  const dlStart = performance.now();
  const stream = sdk.download(obj);
  const downloaded = new Uint8Array(await new Response(stream).arrayBuffer());
  const dlElapsed = (performance.now() - dlStart) / 1000;
  const dlRate = (downloaded.length / 1024 / 1024) / dlElapsed;

  // verify
  const match = downloaded.length === uploadData.length &&
    downloaded.every((b, i) => b === uploadData[i]);
  log(`Download complete: ${downloaded.length} bytes in ${dlElapsed.toFixed(2)}s (${dlRate.toFixed(2)} MiB/s)`);
  log('Data integrity check:', match ? 'PASSED' : 'FAILED');

  // -- share --
  log('\nCreating a sharing key for that object...');
  const key = await sdk.createSharingKey('example', null);
  await key.addObject(obj);
  // The object is still usable here; addObject borrows it rather than
  // consuming the handle.
  log(`Shared object ${obj.id()} under key ${key.publicKey}`);

  const record = await sdk.sharingKey(key);
  log(`The key now grants access to ${record.objectCount} object(s), ${record.objectSize} bytes`);

  // -- read it back as a recipient --
  // The seed is the whole credential. Everything below runs without the app
  // key, as a recipient who was handed nothing else.
  const seed = key.seed();
  log(`\nConnecting as a recipient with seed ${seed.slice(0, 16)}...`);
  const shared = await SharedSdk.connect(INDEXER_URL, seed);

  const stats = await shared.stats();
  log(`Recipient sees ${stats.objectCount} object(s), ${stats.objectSize} bytes`);

  const sharedObj = await shared.object(obj.id());
  const sharedBytes = new Uint8Array(
    await new Response(shared.download(sharedObj)).arrayBuffer(),
  );
  const sharedMatch = sharedBytes.length === uploadData.length &&
    sharedBytes.every((b, i) => b === uploadData[i]);
  log('Recipient download check:', sharedMatch ? 'PASSED' : 'FAILED');

  await key.delete();
  log('Deleted the sharing key');
}

main().catch(err => {
  log('ERROR:', err);
  console.error(err);
});
