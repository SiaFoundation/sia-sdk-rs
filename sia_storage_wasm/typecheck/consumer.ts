// Typechecks the .d.ts that `wasm-pack build` generates, the way a JS consumer
// uses it: import a type, take a value from an SDK method, pass it somewhere
// that expects that type.
//
// This exists because the generated .d.ts is assembled from the
// `typescript_custom_section` blocks in types.rs plus wasm-bindgen's own
// output, and nothing in the Rust build sees the result. A section that
// declares a bare `interface Foo` next to an exported `class Foo` cannot merge
// with it, and every method returning one then hands back a type missing most
// of its members. The Rust still compiles and clippy is happy; only a consumer
// notices.
//
// `skipLibCheck` is false in the tsconfig on purpose. It is what surfaces the
// cause, TS2395 "Individual declarations in merged declaration must be all
// exported or all local", on the .d.ts itself. With it on, only the downstream
// assignability failures appear, and they point at the consumer rather than at
// the declaration that is wrong.
import { SharedSdk } from '../pkg/sia_storage_wasm'
import type { AppKey, Builder, ObjectSummary, PinnedObject, Sdk } from '../pkg/sia_storage_wasm'

declare function useSdk(sdk: Sdk): void
declare function useShared(sdk: SharedSdk): void
declare function useObject(object: PinnedObject): void
declare function useSummary(summary: ObjectSummary): void

export async function check(
  builder: Builder,
  appKey: AppKey,
  indexerUrl: string,
  seed: string,
): Promise<void> {
  // A value from the SDK must satisfy the type the SDK exports for it.
  const sdk = await builder.connected(appKey)
  if (sdk) {
    useSdk(sdk)
    // A member that only the generated class declares.
    sdk.appKey()
  }

  const shared = await SharedSdk.connect(indexerUrl, seed)
  useShared(shared)
  const objects = await shared.objects(0, 1)
  if (objects[0]) {
    useObject(objects[0])
  }
  const summaries = await shared.objectSummaries(0, 1)
  if (summaries[0]) {
    useSummary(summaries[0])
    const size: number = summaries[0].size
    const metadata: Uint8Array = summaries[0].metadata
    const id: string = summaries[0].id
    const times: Date[] = [summaries[0].createdAt, summaries[0].updatedAt]
    void [size, metadata, id, times]
  }
  shared.free()
}
