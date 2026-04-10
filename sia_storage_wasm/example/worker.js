import init, {
  AppKey,
  SdkBuilder,
  SealedObject,
  PinnedObject,
  DownloadOptions,
  UploadOptions,
  generate_recovery_phrase,
  validate_recovery_phrase,
  calculate_encoded_size,
  set_log_level,
} from './pkg/sia_storage_wasm.js';

const APP_ID = '567b03ee1fb87c52af8012e61f3273b987ff6b4c04d9c8cd6e265977d61152b9';
const APP_NAME = 'Sia Storage WASM Demo';
const APP_DESCRIPTION = 'Example app for the Sia Storage SDK';
const APP_SERVICE_URL = 'https://github.com/SiaFoundation/sia-sdk-rs';

let sdk = null;
let builder = null;

function createBuilder(indexerUrl) {
  builder = new SdkBuilder(indexerUrl, APP_ID, APP_NAME, APP_DESCRIPTION, APP_SERVICE_URL);
}

async function sha256hex(data) {
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomData(size) {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i += 65536) {
    crypto.getRandomValues(data.subarray(i, Math.min(i + 65536, size)));
  }
  return data;
}

function status(id, msg) {
  self.postMessage({ id, progress: { status: msg } });
}

async function handleMessage(msg) {
  const { id, type, args } = msg.data;

  try {
    let result;

    switch (type) {
      case 'init':
        await init({ module_or_path: args.wasmUrl });
        if (args.logLevel) set_log_level(args.logLevel);
        result = { ok: true };
        break;

      case 'setLogLevel':
        set_log_level(args.level);
        result = { ok: true };
        break;

      case 'connect': {
        createBuilder(args.indexerUrl);
        const appKey = AppKey.fromHex(args.appKeyHex);
        const sdkResult = await builder.connected(appKey);
        if (sdkResult === null || sdkResult === undefined) {
          result = { connected: false };
        } else {
          sdk = sdkResult;
          result = { connected: true, appKeyHex: appKey.toHex() };
        }
        break;
      }

      case 'generatePhrase':
        result = { phrase: generate_recovery_phrase() };
        break;

      case 'validatePhrase': {
        try {
          validate_recovery_phrase(args.phrase);
          result = { valid: true };
        } catch (e) {
          result = { valid: false, error: e.toString() };
        }
        break;
      }

      case 'requestConnection': {
        createBuilder(args.indexerUrl);
        await builder.requestConnection();
        result = { responseUrl: builder.responseUrl() };
        break;
      }

      case 'waitForApproval':
        await builder.waitForApproval();
        result = { ok: true };
        break;

      case 'register': {
        sdk = await builder.register(args.mnemonic);
        result = { appKeyHex: sdk.appKey().toHex() };
        break;
      }

      case 'account': {
        const a = await sdk.account();
        result = {
          accountKey: a.accountKey,
          maxPinnedData: a.maxPinnedData,
          remainingStorage: a.remainingStorage,
          pinnedData: a.pinnedData,
          pinnedSize: a.pinnedSize,
          ready: a.ready,
          appName: a.appName,
          appDescription: a.appDescription,
        };
        break;
      }

      case 'hosts': {
        const hosts = await sdk.hosts(null);
        result = hosts.map(h => ({
          publicKey: h.publicKey,
          countryCode: h.countryCode,
          goodForUpload: h.goodForUpload,
        }));
        break;
      }

      case 'appKey': {
        const key = sdk.appKey();
        result = {
          hex: key.toHex(),
          publicKey: key.publicKey(),
          exportLength: key.export().length,
        };
        break;
      }

      case 'testAppKey': {
        const key = AppKey.fromHex(args.appKeyHex);
        const message = new TextEncoder().encode('test message');
        const sig = key.sign(message);
        const valid = key.verifySignature(message, sig);
        const pk = key.publicKey();
        const exported = key.export();
        const reimported = new AppKey(exported);
        const sameKey = reimported.publicKey() === pk;
        result = { publicKey: pk, signatureLength: sig.length, valid, exportRoundtrip: sameKey };
        break;
      }

      case 'upload': {
        const data = randomData(args.size);
        const hash = await sha256hex(data);
        const upload = sdk.upload(args.options ? new UploadOptions(
          args.options.dataShards,
          args.options.parityShards,
          args.options.maxInflight,
        ) : null);
        upload.setOnProgress((done) => {
          status(id, 'shard ' + done + ' uploaded');
          postMessage({ id, progress: { shards: done } });
        });
        const chunkSize = 256 * 1024;
        for (let offset = 0; offset < data.length; offset += chunkSize) {
          upload.pushChunk(data.subarray(offset, Math.min(offset + chunkSize, data.length)));
        }
        const obj = await upload.finish();
        await sdk.pinObject(obj);
        result = {
          id: obj.id(),
          size: obj.size(),
          encodedSize: obj.encodedSize(),
          slabCount: obj.slabCount(),
          hash,
        };
        break;
      }

      case 'uploadPacked': {
        const files = [];
        for (const fileSize of args.sizes) {
          const data = randomData(fileSize);
          const hash = await sha256hex(data);
          files.push({ data, hash });
        }
        const packed = sdk.uploadPacked(null);
        for (const f of files) {
          await packed.add(f.data);
        }
        const objects = await packed.finalize();
        const results = [];
        for (let i = 0; i < objects.length; i++) {
          const obj = objects[i];
          await sdk.pinObject(obj);
          results.push({
            id: obj.id(),
            size: obj.size(),
            hash: files[i].hash,
          });
        }
        result = { objects: results };
        break;
      }

      case 'download': {
        const obj = await sdk.object(args.objectId);
        const opts = args.options ? new DownloadOptions(
          args.options.maxInflight,
          args.options.offset,
          args.options.length,
        ) : null;
        const bytes = await sdk.download(obj, opts);
        result = { hash: await sha256hex(bytes), size: bytes.length };
        break;
      }

      case 'downloadStreaming': {
        const obj = await sdk.object(args.objectId);
        const chunks = [];
        let totalSize = 0;
        const opts = args.options ? new DownloadOptions(
          args.options.maxInflight,
          args.options.offset,
          args.options.length,
        ) : null;
        await sdk.downloadStreaming(
          obj,
          (chunk) => { chunks.push(new Uint8Array(chunk)); totalSize += chunk.length; },
          (downloaded, total) => { postMessage({ id, progress: { downloaded, total } }); },
          opts,
        );
        const full = new Uint8Array(totalSize);
        let offset = 0;
        for (const c of chunks) {
          full.set(c, offset);
          offset += c.length;
        }
        result = { hash: await sha256hex(full), size: totalSize };
        break;
      }

      case 'downloadSlab': {
        const obj = await sdk.object(args.objectId);
        const slabData = await sdk.downloadSlab(obj, args.slabIndex);
        result = { hash: await sha256hex(slabData), size: slabData.length };
        break;
      }

      case 'sealOpen': {
        const obj = await sdk.object(args.objectId);
        const appKey = sdk.appKey();
        const sealed = obj.seal(appKey);
        const json = sealed.toJson();
        const restored = SealedObject.fromJson(json);
        const reopened = PinnedObject.open(appKey, restored);
        result = {
          originalId: obj.id(),
          reopenedId: reopened.id(),
          match: obj.id() === reopened.id(),
          sealedJsonLength: json.length,
          slabCount: sealed.slabs().length,
        };
        break;
      }

      case 'shareObject': {
        const obj = await sdk.object(args.objectId);
        const validUntil = Date.now() + 24 * 60 * 60 * 1000;
        const shareUrl = sdk.shareObject(obj, validUntil);
        const shared = await sdk.sharedObject(shareUrl);
        const sharedData = await sdk.download(shared, null);
        result = {
          shareUrl,
          sharedId: shared.id(),
          originalId: obj.id(),
          idMatch: shared.id() === obj.id(),
          hash: await sha256hex(sharedData),
        };
        break;
      }

      case 'metadata': {
        const obj = await sdk.object(args.objectId);
        const originalMeta = obj.metadata();
        const testMeta = new TextEncoder().encode('test-metadata-' + Date.now());
        obj.updateMetadata(testMeta);
        await sdk.updateObjectMetadata(obj);
        const obj2 = await sdk.object(args.objectId);
        const updatedMeta = obj2.metadata();
        const metaMatch = new TextDecoder().decode(updatedMeta) === new TextDecoder().decode(testMeta);
        result = { originalMetaSize: originalMeta.length, updatedMetaSize: updatedMeta.length, metaMatch };
        break;
      }

      case 'objectEvents': {
        const events = await sdk.objectEvents(null, null, 10);
        result = {
          count: events.length,
          events: events.map(e => ({
            id: e.id,
            deleted: e.deleted,
            updatedAt: e.updatedAt,
            size: e.size,
          })),
        };
        break;
      }

      case 'hostAccountBalance': {
        const balance = await sdk.hostAccountBalance(args.hostKey);
        result = { hostKey: args.hostKey, balance };
        break;
      }

      case 'deleteObject':
        await sdk.deleteObject(args.objectId);
        result = { ok: true };
        break;

      case 'encodedSize':
        result = calculate_encoded_size(args.dataSize, args.dataShards, args.parityShards);
        break;

      default:
        throw new Error('unknown message type: ' + type);
    }

    postMessage({ id, result });
  } catch (e) {
    postMessage({ id, error: e.toString() });
  }
}

onmessage = handleMessage;
