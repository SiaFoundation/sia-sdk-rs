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
import { Builder, SharedSdk } from '../examples/index.js'
import type { AppKey, PinnedObject, Sdk, SharingKey, Slab } from '../examples/index.js'

declare function useSdk(sdk: Sdk): void
declare function useShared(sdk: SharedSdk): void
declare function useObject(object: PinnedObject): void
declare function useKey(key: SharingKey): void
declare function useSlab(slab: Slab): void

export async function check(
  builder: Builder,
  appKey: AppKey,
  indexerUrl: string,
  seed: Buffer,
): Promise<void> {
  // A value from the SDK must satisfy the type the SDK exports for it.
  const sdk = await builder.connected(appKey)
  if (sdk) {
    useSdk(sdk)
    const key = await sdk.createSharingKey('photos', null)
    useKey(key)
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
}
