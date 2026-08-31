---
emoji: 🦀
name: Update sia-storage-js
description: On a sia_storage_napi and sia_storage_wasm release, open a pull request in SiaFoundation/sia-storage-js that bumps the pinned Rust SDK, repairs the build, wraps newly exported bindings, and verifies the result with typecheck and the install integration test.
on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      release_tag:
        description: "sia_storage_napi or sia_storage_wasm tag to update to. Defaults to the newest stable napi release."
        required: false
        type: string
if: >-
  github.event_name != 'release'
  || startsWith(github.event.release.tag_name, 'sia_storage_napi/v')
  || startsWith(github.event.release.tag_name, 'sia_storage_wasm/v')
permissions:
  contents: read
  copilot-requests: write
# `opus` is a built-in catalog alias (copilot/*opus*). Pinned because Copilot's
# default `auto` is absent from AWF's pricing table, and the API proxy rejects
# every inference request with HTTP 400 for a model it cannot price.
model: opus
# Fallback pricing in case the alias ever resolves to an unpriced model.
# Rates are gh-aw's conservative GPT-4-class defaults ($/1M tokens).
models:
  default-ai-credits-pricing:
    input: 5.0
    output: 25.0
# A release burst publishes the napi and wasm releases seconds apart, so both
# fire this workflow. Only the last run matters — it is the one that can see
# both tags — so let each new run cancel the one before it.
concurrency:
  group: update-sia-storage-js
  cancel-in-progress: true
runs-on: ubuntu-latest
timeout-minutes: 45
network:
  allowed:
    - defaults
    - github
    - node
    - rust
tools:
  bash: ["*"]
  edit:
checkout:
  - repository: SiaFoundation/sia-storage-js
    ref: main
    path: sia-storage-js
steps:
  - name: Setup Bun
    uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6 # v2.2.0
  - name: Setup Node
    uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
    with:
      node-version: 24
  - name: Setup Rust
    run: |
      rustup update stable
      rustup target add wasm32-unknown-unknown
  - name: Cache Rust target + registry
    uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
    with:
      workspaces: sia-storage-js/rust/sia-sdk-rs
      shared-key: napi-linux-x64
  - name: Install wasm-pack
    run: cargo install wasm-pack --locked
  - name: Prepare Rust SDK checkout and binding diff
    working-directory: sia-storage-js
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      RELEASE_TAG: ${{ github.event.release.tag_name || inputs.release_tag }}
    run: |
      set -euo pipefail
      mkdir -p /tmp/gh-aw

      current_napi=$(jq -r .napi .sia-sdk-rs.json)
      current_wasm=$(jq -r .wasm .sia-sdk-rs.json)

      # A release event names the tag that fired; a manual run either supplies
      # one or falls back to the newest stable napi release.
      anchor_tag="${RELEASE_TAG:-}"
      if [ -z "$anchor_tag" ]; then
        anchor_tag=$(gh api repos/SiaFoundation/sia-sdk-rs/releases --paginate \
          --jq '[.[] | select(.prerelease == false) | .tag_name
                 | select(startswith("sia_storage_napi/v"))] | first')
      fi

      # Same path scripts/setup-rust.ts clones into, so `bun run setup` is a
      # no-op and build-wasm / setup-napi-test find the crates where they expect
      # them. Unshallow, unlike setup-rust.ts, so the tags can be diffed.
      git clone --filter=blob:none https://github.com/SiaFoundation/sia-sdk-rs.git rust/sia-sdk-rs
      git -C rust/sia-sdk-rs checkout --detach "$anchor_tag"
      anchor_sha=$(git -C rust/sia-sdk-rs rev-parse HEAD)

      tag_at() {
        git -C rust/sia-sdk-rs tag --points-at "$anchor_sha" --list "$1/v*" | sort -V | tail -1
      }

      # The release job tags both crates on one commit, but the two releases
      # publish 1-2s apart, so whichever tag did not fire this run can briefly
      # still be missing.
      target_napi=""
      target_wasm=""
      for _ in $(seq 1 10); do
        target_napi=$(tag_at sia_storage_napi)
        target_wasm=$(tag_at sia_storage_wasm)
        if [ -n "$target_napi" ] && [ -n "$target_wasm" ]; then
          break
        fi
        sleep 6
        git -C rust/sia-sdk-rs fetch --tags --quiet
      done

      # A crate with no tag on the anchor commit keeps its current pin.
      both_tagged=true
      if [ -z "$target_napi" ]; then target_napi="$current_napi"; both_tagged=false; fi
      if [ -z "$target_wasm" ]; then target_wasm="$current_wasm"; both_tagged=false; fi

      jq -n \
        --arg current_napi "$current_napi" --arg current_wasm "$current_wasm" \
        --arg target_napi "$target_napi" --arg target_wasm "$target_wasm" \
        --arg anchor_tag "$anchor_tag" --arg anchor_sha "$anchor_sha" \
        --argjson both_tagged "$both_tagged" \
        '{current: {napi: $current_napi, wasm: $current_wasm},
          target: {napi: $target_napi, wasm: $target_wasm},
          anchor: {tag: $anchor_tag, sha: $anchor_sha},
          both_tagged: $both_tagged,
          pin_already_current: ($current_napi == $target_napi and $current_wasm == $target_wasm)}' \
        > /tmp/gh-aw/sdk-update.json
      cat /tmp/gh-aw/sdk-update.json

      # Binding-surface diff from the old napi pin to the anchor commit.
      # Truncated so it cannot swamp the agent's context; the full tree is on
      # disk either way.
      if git -C rust/sia-sdk-rs rev-parse -q --verify "$current_napi^{commit}" >/dev/null; then
        git -C rust/sia-sdk-rs diff "$current_napi".."$anchor_sha" \
          -- sia_storage_napi/src sia_storage_wasm/src \
          | head -c 400000 > /tmp/gh-aw/bindings.diff
      else
        echo "previous tag $current_napi not found; diff unavailable" > /tmp/gh-aw/bindings.diff
      fi

      for crate in sia_core sia_storage sia_storage_napi sia_storage_wasm; do
        echo "## $crate"
        git -C rust/sia-sdk-rs show "$anchor_sha:$crate/CHANGELOG.md" 2>/dev/null | head -60
        echo
      done > /tmp/gh-aw/changelog.md
safe-outputs:
  # Pull requests are authored by the app's bot identity rather than a
  # developer's PAT. The token is minted per run and scoped to just the one
  # target repository.
  github-app:
    client-id: ${{ secrets.SIA_CI_BOT_APP_ID }}
    private-key: ${{ secrets.SIA_CI_BOT_PRIVATE_KEY }}
    owner: SiaFoundation
    repositories: [sia-storage-js]
  create-pull-request:
    target-repo: SiaFoundation/sia-storage-js
    title-prefix: "chore: "
    labels: [dependencies]
    draft: false
    allowed-files:
      - ".sia-sdk-rs.json"
      - ".changeset/**"
      - "src/**"
      - "scripts/**"
      - "tsup.config.ts"
    protected-files:
      policy: request_review
      exclude: [".changeset/"]
---

# Update sia-storage-js for a new Rust SDK release

`SiaFoundation/sia-storage-js` is the TypeScript wrapper around this repository's
`sia_storage_napi` and `sia_storage_wasm` crates. A release here means that wrapper
needs to move forward. Your job is to move it forward and open one pull request.

## What is already set up

- `sia-storage-js/` is a checkout of `SiaFoundation/sia-storage-js` (branch `main`).
  **Every command and every edit below happens inside that directory** — the workspace
  root is a checkout of this repository and is not what you are changing.
- `sia-storage-js/rust/sia-sdk-rs/` is a checkout of this repository at the anchor
  commit — the commit the triggering release tagged, and the same path
  `scripts/setup-rust.ts` clones into. It is gitignored, so nothing under it can reach
  the pull request.
- Bun, Node 24, a stable Rust toolchain with `wasm32-unknown-unknown`, and `wasm-pack`
  are installed.
- `/tmp/gh-aw/sdk-update.json` — current pins, target pins, the anchor tag and commit,
  whether both crates were tagged on that commit, and whether the pin is already current.
- `/tmp/gh-aw/bindings.diff` — the diff of `sia_storage_napi/src` and `sia_storage_wasm/src`
  between the current and target tags. This is the primary signal for what changed.
- `/tmp/gh-aw/changelog.md` — changelog heads for the released crates.

If `both_tagged` is false, only one of the two crates was released on the anchor commit,
so the other keeps its existing pin. That breaks the assumption `.github/workflows/ci.yml`
and `scripts/setup-rust.ts` are built on — one clone at the napi tag serving both crates —
because the two pins now name different commits. Do not paper over it: finish the update
if you can, and state the divergence prominently at the top of the pull request body.

## Task

1. **Update the pin.** Set `napi` and `wasm` in `.sia-sdk-rs.json` to the target tags.
   If `pin_already_current` is true the daily `check-sdk-update.yml` job already landed
   the bump — leave the file and the existing changeset alone and continue to step 2,
   since the wrapper work may still be outstanding.

2. **Build.** Run, in order:

   ```
   bun install
   bun run setup-napi-test
   bun run build
   bun run typecheck
   bun test src/tests/install-integration.test.ts
   ```

   `setup-napi-test` builds the NAPI binary for this runner (`linux-x64-gnu`), stages it
   into `node_modules`, and regenerates the gitignored `src/node/napi.generated.d.ts`.
   `bun run build` builds WASM, bundles with tsup, and emits the Node type entrypoint.

3. **Fix what broke.** Repair failures in `src/` and `scripts/` caused by the SDK bump —
   renamed or removed exports, changed signatures, changed generated type names. Fix the
   cause, not the symptom: if a type name changed upstream, follow the rename through
   rather than casting it away. Never silence an error with `any` or `@ts-ignore`.

4. **Wrap new types and methods.** The wrapper re-exports the bindings by hand through
   two surfaces. Both are hand-maintained lists — extend them, do not restructure them:

   - `src/index.ts` (browser/WASM): add new classes and functions to the
     `export { … } from '../wasm/sia_storage_wasm.js'` block and new types to the
     `export type { … }` block. Both are alphabetized, classes before functions.
   - `src/node/napi.ts` (Node/NAPI): add new classes and functions to the
     `export const { … } = addon` destructuring. Types need no change — they flow from
     `export type * from './napi.generated'`. This list groups classes first, then
     functions, and is not alphabetized; append within the matching group.

   Only export bindings the crates actually expose at the target tag. Confirm each one
   against `rust/sia-sdk-rs/sia_storage_wasm/src` or the regenerated
   `src/node/napi.generated.d.ts` before adding it — do not infer an export from the
   changelog alone. Keep the two surfaces consistent: a binding exposed by both crates
   should appear in both files.

   Do not invent new abstractions, helper wrappers, re-shaped APIs, or new files. If a
   new binding genuinely cannot be expressed in the existing structure, leave it out and
   say so in the pull request body.

5. **Re-run the full sequence from step 2** until `typecheck` and the install integration
   test pass. If you cannot get them green, still open the pull request, but say plainly
   at the top of the body what is failing and paste the error.

6. **Write the changeset.** Create `.changeset/sdk-update.md` (skip if step 1 found the
   pin already current and the changeset already exists), matching the format
   `check-sdk-update.yml` uses so the two paths do not produce conflicting entries:

   ```
   ---
   default: patch
   ---

   #### Update sia-sdk-rs (napi v0.0.0, wasm v0.0.0)
   ```

   Use `minor` instead of `patch` when the update adds new exports to the wrapper's public
   surface. Strip the `sia_storage_napi/` and `sia_storage_wasm/` prefixes from the tags in
   the heading. If the entry needs more than the heading, follow it with prose — not a list.

## Output

Emit one `create_pull_request` targeting `SiaFoundation/sia-storage-js`. Title it
`update sia-sdk-rs (napi vX.Y.Z, wasm vX.Y.Z)` (the `chore: ` prefix is added for you).
The body should cover, in prose:

- the version move, and the upstream changes that motivated it
- every export added to `src/index.ts` and `src/node/napi.ts`, and what each one is for
- every build or type break you fixed, and how
- anything left undone: a binding you could not wrap, a failing check, or a tag divergence

Call `noop` with a short explanation instead of opening a pull request when the pin is
already current, the build and typecheck pass untouched, and the release exposes no new
bindings — that is the expected outcome for a release that only changes crate internals.
