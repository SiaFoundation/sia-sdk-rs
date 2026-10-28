// Typechecks the index.d.ts that `napi build` generates, the way a Node
// consumer uses it: import a type, take a value from an SDK method, pass it
// somewhere that expects that type.
//
// The wasm bindings have had the generated declarations break twice without CI
// noticing, because nothing in the Rust build looks at the emitted TypeScript.
// This binding emits a .d.ts the same way and is exposed to the same class of
// problem: a duplicate or self referential declaration compiles on the Rust
// side and only fails for whoever imports it.
//
// `skipLibCheck` is false in the tsconfig on purpose, so the declarations
// themselves are checked rather than only the code below.
import { Builder, PreAuthorizedKey, SharedSdk } from '../examples/index.js'
import type {
  AppKey,
  ObjectEventSummary,
  ObjectSummary,
  PinnedObject,
  PreAuthorizedKeyRequest,
  Sdk,
  SharingKey,
  SignedPreAuthorizedKeyRequest,
  Slab,
} from '../examples/index.js'

declare function useSdk(sdk: Sdk): void
declare function useShared(sdk: SharedSdk): void
declare function useObject(object: PinnedObject): void
declare function useKey(key: SharingKey): void
declare function useSlab(slab: Slab): void
declare function useSummary(summary: ObjectSummary): void
declare function useEventSummary(event: ObjectEventSummary): void

export async function check(
  builder: Builder,
  appKey: AppKey,
  indexerUrl: string,
  seed: Buffer,
): Promise<void> {
  const generatedKey = new PreAuthorizedKey()
  const keySeed: Buffer = generatedKey.export()
  const preAuthorizedKey = PreAuthorizedKey.import(keySeed)
  const publicKey: string = preAuthorizedKey.publicKey()
  const message = Buffer.from('message')
  const signature: Buffer = preAuthorizedKey.sign(message)
  const valid: boolean = preAuthorizedKey.verifySignature(message, signature)
  const requestOptions: PreAuthorizedKeyRequest = {
    connectKey: 'connect-key',
    expiration: new Date(),
    totalUses: 1,
    allowedAppID: '03'.repeat(32),
  }
  const request: SignedPreAuthorizedKeyRequest = preAuthorizedKey.signRequest(requestOptions)
  const requestStrings: string[] = [
    request.publicKey, request.signature, request.connectKey, request.expiration,
  ]
  const requestTotalUses: number = request.totalUses
  const requestAppID: string | undefined = request.allowedAppID
  const unrestrictedRequest: SignedPreAuthorizedKeyRequest = preAuthorizedKey.signRequest({
    connectKey: 'connect-key',
    expiration: new Date(),
    totalUses: 1,
  })
  const nullAppID: SignedPreAuthorizedKeyRequest = preAuthorizedKey.signRequest({
    ...requestOptions, allowedAppID: null,
  })
  // @ts-expect-error The signed request is an object, not JSON text.
  const requestText: string = preAuthorizedKey.signRequest(requestOptions)
  // @ts-expect-error Expiration must be a Date.
  preAuthorizedKey.signRequest({ ...requestOptions, expiration: Date.now() })
  // @ts-expect-error A request must include totalUses.
  preAuthorizedKey.signRequest({ connectKey: 'connect-key', expiration: new Date() })
  // @ts-expect-error The application restriction uses allowedAppID.
  preAuthorizedKey.signRequest({ ...requestOptions, allowedAppId: '03'.repeat(32) })
  // @ts-expect-error Signing accepts one request object.
  preAuthorizedKey.signRequest('connect-key', new Date(), 1)
  const preAuthorizedSdk: Promise<Sdk> = builder.connectPreAuthorized(preAuthorizedKey, 'mnemonic')
  // @ts-expect-error Connecting requires a PreAuthorizedKey object, not its seed.
  builder.connectPreAuthorized(keySeed, 'mnemonic')
  // @ts-expect-error Registration requires the user's mnemonic.
  builder.connectPreAuthorized(preAuthorizedKey)
  void [publicKey, valid, request, unrestrictedRequest, nullAppID, preAuthorizedSdk]
  void [requestStrings, requestTotalUses, requestAppID, requestText]

  // A value from the SDK must satisfy the type the SDK exports for it.
  const sdk = await builder.connected(appKey)
  if (sdk) {
    useSdk(sdk)
    const key = await sdk.createSharingKey('photos', null)
    useKey(key)
    const events = await sdk.objectEventSummaries(null, 1)
    if (events[0]) {
      useEventSummary(events[0])
      const id: string = events[0].id
      const deleted: boolean = events[0].deleted
      const updatedAt: Date = events[0].updatedAt
      const object: ObjectSummary | null = events[0].object
      const next = await sdk.objectEventSummaries({ id, after: updatedAt }, 1)
      void [id, deleted, updatedAt, object, next]
    }
  }

  const shared = await SharedSdk.connect(indexerUrl, seed)
  useShared(shared)
  const objects = await shared.objects(0, 1)
  if (objects[0]) {
    useObject(objects[0])
    for (const slab of objects[0].slabs()) {
      useSlab(slab)
    }
  }
  const summaries = await shared.objectSummaries(0, 1)
  if (summaries[0]) {
    useSummary(summaries[0])
    const size: bigint = summaries[0].size
    const metadata: Buffer = summaries[0].metadata
    const id: string = summaries[0].id
    const times: Date[] = [summaries[0].createdAt, summaries[0].updatedAt]
    void [size, metadata, id, times]
  }
}
