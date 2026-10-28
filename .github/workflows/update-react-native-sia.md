---
emoji: 📱
name: Update react-native-sia
description: On a sia_storage_ffi release, open a pull request in SiaFoundation/react-native-sia that repins the crate, regenerates the uniffi-bindgen-react-native bindings, and adapts the public surface and example app to any API change.
on:
  bots: ["sia-ci-bot[bot]"]
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      release_tag:
        description: "sia_storage_ffi tag to update to. Defaults to the newest stable release."
        required: false
        type: string
if: github.event_name != 'release' || startsWith(github.event.release.tag_name, 'sia_storage_ffi/v')
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
# Every crate in a release fires this workflow within seconds. The `if:` above
# is checked per job, after the run has joined this group, so a run it skips
# still cancels the one before it. Only ffi and manual runs share the group.
concurrency:
  group: >-
    ${{ (github.event_name != 'release'
    || startsWith(github.event.release.tag_name, 'sia_storage_ffi/v'))
    && 'update-react-native-sia'
    || format('update-react-native-sia-{0}', github.run_id) }}
  cancel-in-progress: true
runs-on: ubuntu-latest
timeout-minutes: 90
network:
  allowed:
    - defaults
    - github
    - rust
    - node
    - linux-distros
tools:
  bash: ["*"]
  edit:
checkout:
  - repository: SiaFoundation/react-native-sia
    ref: main
    path: react-native-sia
steps:
  - name: Setup Node
    uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
    with:
      node-version-file: react-native-sia/.nvmrc
  - name: Setup Rust
    # ubrn builds the staticlib for Android, so the target has to be installed
    # before `ubrn build`. Nightly matches what the target repo's own CI uses.
    uses: dtolnay/rust-toolchain@5b842231ba77f5c045dba54ac5560fed2db780e2 # nightly
    with:
      targets: aarch64-linux-android
  - name: Install native tooling
    # clang-format is what ubrn shells out to for the generated C++. cargo-ndk
    # drives the Android cross build, bindgen generates the FFI header.
    run: |
      set -euo pipefail
      sudo apt-get update || true
      sudo apt-get install -y clang-format
      cargo install --force --locked bindgen-cli
      cargo install --force --locked cargo-ndk@^3
  - name: Repin sia_storage_ffi and prepare context
    working-directory: react-native-sia
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      RELEASE_TAG: ${{ github.event.release.tag_name || inputs.release_tag }}
      UPSTREAM_REPO: SiaFoundation/sia-sdk-rs
      TAG_PREFIX: sia_storage_ffi/v
    run: |
      set -euo pipefail
      mkdir -p /tmp/gh-aw

      # gh-aw checks this repository out at the workspace root, so the
      # react-native-sia checkout lands inside this repo's cargo workspace and
      # cargo refuses to touch it as a non-member. Move ours aside for the run
      # rather than making either repo accommodate the runner layout. Nothing
      # here builds sia-sdk-rs from the root checkout.
      if [ -f "$GITHUB_WORKSPACE/Cargo.toml" ]; then
        mv "$GITHUB_WORKSPACE/Cargo.toml" "$RUNNER_TEMP/sia-sdk-rs-root-Cargo.toml"
      fi

      current_tag=$(sed -n 's/^[[:space:]]*branch:[[:space:]]*\(.*\)$/\1/p' ubrn.config.yaml | head -1)
      : "${current_tag:?Could not read the pinned tag from ubrn.config.yaml}"

      tag="${RELEASE_TAG:-}"
      if [ -z "$tag" ]; then
        tag=$(gh release list --repo "$UPSTREAM_REPO" --limit 100 \
          --exclude-drafts --exclude-pre-releases --json tagName --jq '.[].tagName' \
          | grep "^$TAG_PREFIX" | sort -V | tail -n1)
      fi
      : "${tag:?No stable $TAG_PREFIX release found}"
      version="${tag#"$TAG_PREFIX"}"
      current_version="${current_tag#"$TAG_PREFIX"}"

      changed=true
      reason=""
      if [ "$current_tag" = "$tag" ]; then
        changed=false
        reason="already pinned to $tag"
      elif [ "$(printf '%s\n%s\n' "$current_version" "$version" | sort -V | tail -n1)" != "$version" ]; then
        changed=false
        reason="refusing to downgrade from $current_version to $version"
      fi

      # Mechanical repin, matching what check-sdk-update.yml used to do so the
      # two paths cannot disagree about which file carries the version.
      # The | delimiter keeps the tag's slash literal.
      if [ "$changed" = true ]; then
        sed -i -E "s|^([[:space:]]*branch:[[:space:]]*).*|\1${tag}|" ubrn.config.yaml
        grep -qF "branch: $tag" ubrn.config.yaml

        # The delimiter is built rather than written literally: a line of three
        # dashes inside this script ends the workflow's own frontmatter, which
        # drops everything below it, safe-outputs included.
        fence=$(printf -- '-%.0s' 1 2 3)
        mkdir -p .changeset
        {
          echo "$fence"
          echo "default: patch"
          echo "$fence"
          echo
          echo "#### Update Sia SDK to ${version}"
          echo
          echo "See the [sia-sdk-rs release notes](https://github.com/$UPSTREAM_REPO/releases/tag/${tag})."
        } > .changeset/sdk-update.md
      fi

      # Cloned outside the checkout so it cannot land in the patch. Unshallow so
      # the FFI surface can be diffed across the two tags.
      git clone --filter=blob:none "https://github.com/$UPSTREAM_REPO.git" /tmp/gh-aw/sia-sdk-rs

      jq -n \
        --arg current_tag "$current_tag" --arg current_version "$current_version" \
        --arg tag "$tag" --arg version "$version" \
        --arg reason "$reason" --argjson changed "$changed" \
        '{current: {tag: $current_tag, version: $current_version},
          target: {tag: $tag, version: $version},
          repinned: $changed,
          skip_reason: $reason}' \
        > /tmp/gh-aw/sdk-update.json
      cat /tmp/gh-aw/sdk-update.json

      # FFI surface diff across the two tags. Truncated so it cannot swamp the
      # agent's context, the full tree is at /tmp/gh-aw/sia-sdk-rs either way.
      git -C /tmp/gh-aw/sia-sdk-rs diff "$current_tag".."$tag" -- sia_storage_ffi/src \
        | head -c 400000 > /tmp/gh-aw/ffi.diff

      for crate in sia_core sia_storage sia_storage_ffi; do
        echo "## $crate"
        git -C /tmp/gh-aw/sia-sdk-rs show "$tag:$crate/CHANGELOG.md" 2>/dev/null | head -60
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
    repositories: [react-native-sia]
  create-pull-request:
    target-repo: SiaFoundation/react-native-sia
    title-prefix: "chore: "
    labels: [dependencies]
    draft: false
    protected-files:
      policy: request_review
      exclude:
        - .changeset/
    allowed-files:
      - "ubrn.config.yaml"
      - ".changeset/**"
      - "src/**"
      - "example/**"
      - "package.json"
      - "README.md"
---

# Update react-native-sia for a new sia_storage_ffi release

`SiaFoundation/react-native-sia` wraps this repository's `sia_storage_ffi` crate for
React Native through `uniffi-bindgen-react-native`. The repin and the changeset are
already done for you. Your job is to prove the new crate still generates working
bindings, and to adapt the hand-written surface when the release changed the API.

## What makes this repo different

Almost everything under `src/` is generated and gitignored: `src/index.ts`,
`src/generated/`, `src/Native*`, plus `cpp/`, `ios/`, and parts of `android/`. A clean
checkout contains only two hand-written TypeScript files, `src/public.ts` and
`src/__tests__/index.test.tsx`. So a release that renames or removes an export produces
no diff on its own. It surfaces as a build failure, or silently as a public API that no
longer matches what the example app calls.

That is what you are here to catch.

## What is already set up

- `react-native-sia/` is a checkout of `SiaFoundation/react-native-sia` (branch `main`).
  **Every command and every edit below happens inside that directory.**
- The repin is applied and verified there: the `branch:` line in `ubrn.config.yaml`, plus
  a `.changeset/sdk-update.md` naming the new version. Do not redo either by hand.
- Node (from `.nvmrc`), Rust nightly with the `aarch64-linux-android` target,
  `clang-format`, `bindgen-cli`, and `cargo-ndk` are installed.
- The workspace root holds a checkout of this repository, but its `Cargo.toml` has been
  moved aside so cargo treats the generated Rust checkout as standalone. Do not restore
  it, and do not build anything from the root checkout.
- `/tmp/gh-aw/sdk-update.json` holds the old and new tag and version, whether the repin
  happened, and why not if it did not.
- `/tmp/gh-aw/ffi.diff` is the diff of `sia_storage_ffi/src` between the two tags. This
  is the primary signal for what changed in the FFI surface.
- `/tmp/gh-aw/changelog.md` holds changelog heads for `sia_core`, `sia_storage`, and
  `sia_storage_ffi`.
- `/tmp/gh-aw/sia-sdk-rs/` is a full checkout of this repository, for reading the crate
  source when the diff is not enough.

If `repinned` is false, read `skip_reason`. Either the pin is already current or the
release would be a downgrade. Nothing was modified, so call `noop` and stop.

## Task

1. **Install and generate the bindings.** From `react-native-sia/`:

   ```
   yarn install --immutable
   yarn ubrn:checkout
   CARGO_PROFILE_RELEASE_LTO=off RUSTFLAGS="-C embed-bitcode=no" \
     npx ubrn build android --and-generate --release --targets arm64-v8a
   ```

   `ubrn:checkout` clones the crate at the tag now pinned in `ubrn.config.yaml`, so this
   is the first real test that the new release builds at all. Android alone is enough.
   Generating for one ABI exercises the same code generation as all of them, and the
   iOS half needs a macOS toolchain this runner does not have.

2. **Read what the release did to the public surface.** Compare the regenerated
   `src/index.ts` against the exports the repo actually uses:

   - `src/public.ts` re-exports everything and aliases `uniffiInitAsync` to `initSia`.
     If an export it names disappeared or was renamed, fix it here.
   - `example/src/App.tsx` is the only real consumer in the repo. It calls `Builder`,
     `AppKey`, `PinnedObject`, `generateRecoveryPhrase`, and the `Sdk` and `Reader`
     types. A signature change shows up here first.
   - `scripts/check-package.mjs` compiles a file importing `initSia` and
     `generateRecoveryPhrase` by name. If either moved, that check fails, and the rename
     belongs in the pull request body because consumers will hit it too.

3. **Verify.**

   ```
   yarn typecheck
   yarn lint
   yarn test
   yarn prepare && yarn test:package
   ```

   `test:package` packs the tarball and checks that every advertised entry point exists
   and that a consumer file still typechecks against the built output. It is the closest
   thing here to an integration test, so do not skip it.

4. **Fix what broke.** Extend the existing structure, do not restructure it, and do not
   add files. If the release only changed crate internals, nothing under `src/` or
   `example/` should need editing, and that is the normal outcome. Never silence a
   failure by deleting a test, an export, or a call site.

5. **Re-run step 3 until it is green.** If you cannot get there, still open the pull
   request, but say plainly at the top of the body what is failing and paste the error.

**iOS cannot be built here.** This runner is Linux. The target repository's own CI builds
the iOS framework and the example app on macOS when the pull request opens. Say that
rather than implying iOS passed.

6. **Check the changed files.** Run `git status` and revert anything outside
   `ubrn.config.yaml`, `.changeset/`, `src/`, `example/`, `package.json`, and
   `README.md`. Generated output is gitignored and must not be committed. Any other file
   rejects the whole pull request, so list what you reverted in the body.

## Output

Emit one `create_pull_request` targeting `SiaFoundation/react-native-sia`. Title it
`update SDK to X.Y.Z` (the `chore: ` prefix is added for you). The body should cover, in
prose:

- the version move, and the upstream changes that motivated it
- whether the generated surface changed, and every hand-written file you edited
- which checks you ran and their result, and that iOS was not built
- anything left undone, such as a rename consumers will have to absorb

Call `noop` with a short explanation instead of opening a pull request when `repinned` is
false. When the repin is real, always open one, even if nothing else changed: the pinned
tag and the changeset are the point, and a release that only touches crate internals
still needs to ship.
