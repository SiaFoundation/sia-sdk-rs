---
emoji: 🧬
name: Update sia-storage-sdk
description: On a sia_storage_ffi release, open a pull request in SiaFoundation/sia-storage-sdk that repins the crate, regenerates the UniFFI bindings, and updates the hand-written Python, Swift, and Kotlin wrappers.
on:
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
concurrency:
  group: update-sia-storage-sdk
  cancel-in-progress: true
runs-on: ubuntu-latest
timeout-minutes: 60
network:
  allowed:
    - defaults
    - github
    - rust
    - python
    - java
    - linux-distros
tools:
  bash: ["*"]
  edit:
checkout:
  - repository: SiaFoundation/sia-storage-sdk
    ref: master
    path: sia-storage-sdk
steps:
  - name: Setup Rust
    uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable
  - name: Setup Python
    uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
    with:
      python-version: '3.12'
  - name: Setup JDK
    uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
    with:
      distribution: temurin
      java-version: '17'
  - name: Setup Gradle
    uses: gradle/actions/setup-gradle@748248ddd2a24f49513d8f472f81c3a07d4d50e1 # v4.4.4
    with:
      gradle-version: '8.10.2'
  - name: Install maturin
    run: pip install 'maturin>=1.8,<2.0'
  - name: Cache Rust target + registry
    uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
    with:
      workspaces: sia-storage-sdk
      shared-key: ffi-linux-x64
  - name: Repin sia_storage_ffi and prepare context
    working-directory: sia-storage-sdk
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      RELEASE_TAG: ${{ github.event.release.tag_name || inputs.release_tag }}
      UPSTREAM_REPO: SiaFoundation/sia-sdk-rs
      TAG_PREFIX: sia_storage_ffi/v
    run: |
      set -euo pipefail
      mkdir -p /tmp/gh-aw

      current_rev=$(sed -n 's/^sia_storage_ffi = {.*rev = "\([0-9a-f]\{40\}\)".*/\1/p' Cargo.toml)
      current_version=$(sed -n '0,/^version = /s/^version = "\(.*\)"/\1/p' Cargo.toml)
      : "${current_rev:?Could not read sia_storage_ffi rev from Cargo.toml}"
      : "${current_version:?Could not read package version from Cargo.toml}"

      tag="${RELEASE_TAG:-}"
      if [ -z "$tag" ]; then
        tag=$(gh release list --repo "$UPSTREAM_REPO" --limit 100 \
          --exclude-drafts --exclude-pre-releases --json tagName --jq '.[].tagName' \
          | grep "^$TAG_PREFIX" | sort -V | tail -n1)
      fi
      : "${tag:?No stable $TAG_PREFIX release found}"
      version="${tag#"$TAG_PREFIX"}"

      # Cloned outside the checkout so it cannot land in the patch. Unshallow so
      # the FFI surface can be diffed across the two revs.
      git clone --filter=blob:none "https://github.com/$UPSTREAM_REPO.git" /tmp/gh-aw/sia-sdk-rs
      rev=$(git -C /tmp/gh-aw/sia-sdk-rs rev-parse "$tag^{commit}")

      changed=true
      reason=""
      if [ "$current_rev" = "$rev" ]; then
        changed=false
        reason="already pinned to $rev"
      elif [ "$(printf '%s\n%s\n' "$current_version" "$version" | sort -V | tail -n1)" != "$version" ]; then
        changed=false
        reason="refusing to downgrade from $current_version to $version"
      fi

      # Mechanical version mirroring, matching check-sdk-update.yml so the two
      # paths cannot disagree about which files carry the version.
      if [ "$changed" = true ]; then
        sed -i "s|rev = \"$current_rev\"|rev = \"$rev\"|" Cargo.toml
        sed -i "0,/^version = /s/^version = \".*\"/version = \"$version\"/" Cargo.toml
        sed -i -E "s|/releases/download/v[0-9.]+/SiaStorageSDKFFI-[0-9.]+\.xcframework\.zip|/releases/download/v$version/SiaStorageSDKFFI-$version.xcframework.zip|" Package.swift
        sed -i -E "s|(s\.version[[:space:]]*=[[:space:]]*')[^']*'|\1$version'|" SiaStorageSDK.podspec
        sed -i -E "s|^version=.*|version=$version|" kotlin/gradle.properties examples/kotlin/gradle.properties
        sed -i -E "s|tech\.sia:siastoragesdk:[0-9.]+|tech.sia:siastoragesdk:$version|" kotlin/README.md examples/kotlin/README.md
        sed -i -E \
          -e "s|(sia-storage-sdk\", from: \")[0-9.]+\"|\1$version\"|" \
          -e "s|(pod 'SiaStorageSDK', '~> )[0-9.]+'|\1$version'|" \
          swift/README.md

        grep -qF "rev = \"$rev\"" Cargo.toml
        for file in Cargo.toml Package.swift SiaStorageSDK.podspec \
          kotlin/gradle.properties examples/kotlin/gradle.properties \
          kotlin/README.md examples/kotlin/README.md swift/README.md; do
          grep -qF "$version" "$file"
        done

        # The new rev can require newer transitive deps than Cargo.lock pins, so
        # re-resolve the git dependency rather than relying on fetch alone.
        cargo update --package sia_storage_ffi
        cargo fetch --target "$(rustc -vV | sed -n 's/^host: //p')"
        locked=$(cargo metadata --format-version 1 \
          | jq -r '.packages[] | select(.name == "sia_storage_ffi") | .version')
        [ "$locked" = "$version" ] || {
          echo "Cargo.lock resolved sia_storage_ffi $locked, expected $version" >&2
          exit 1
        }
      fi

      jq -n \
        --arg current_rev "$current_rev" --arg current_version "$current_version" \
        --arg rev "$rev" --arg version "$version" --arg tag "$tag" \
        --arg reason "$reason" --argjson changed "$changed" \
        '{current: {rev: $current_rev, version: $current_version},
          target: {rev: $rev, version: $version, tag: $tag},
          repinned: $changed,
          skip_reason: $reason}' \
        > /tmp/gh-aw/sdk-update.json
      cat /tmp/gh-aw/sdk-update.json

      # FFI surface diff across the two revs. Truncated so it cannot swamp the
      # agent's context; the full tree is at /tmp/gh-aw/sia-sdk-rs either way.
      git -C /tmp/gh-aw/sia-sdk-rs diff "$current_rev".."$rev" -- sia_storage_ffi/src \
        | head -c 400000 > /tmp/gh-aw/ffi.diff

      for crate in sia_core sia_storage sia_storage_ffi; do
        echo "## $crate"
        git -C /tmp/gh-aw/sia-sdk-rs show "$rev:$crate/CHANGELOG.md" 2>/dev/null | head -60
        echo
      done > /tmp/gh-aw/changelog.md
safe-outputs:
  create-pull-request:
    target-repo: SiaFoundation/sia-storage-sdk
    github-token: ${{ secrets.RELEASE_PAT }}
    title-prefix: "chore: "
    labels: [dependencies]
    draft: false
    allowed-files:
      - "Cargo.toml"
      - "Cargo.lock"
      - "Package.swift"
      - "SiaStorageSDK.podspec"
      - "python/**"
      - "swift/**"
      - "kotlin/**"
      - "examples/**"
    protected-files:
      policy: request_review
      exclude: ["gradle.properties", "README.md"]
---

# Update sia-storage-sdk for a new sia_storage_ffi release

`SiaFoundation/sia-storage-sdk` exposes this repository's `sia_storage_ffi` crate to
Python, Swift, and Kotlin through UniFFI. Each language has generated bindings plus a
hand-written wrapper layer on top. The repin and version mirroring are already done for
you; your job is everything a `sed` cannot do — regenerate the bindings, make all three
languages build again, and extend the wrappers to cover what the release added.

## What is already set up

- `sia-storage-sdk/` is a checkout of `SiaFoundation/sia-storage-sdk` (branch `master`).
  **Every command and every edit below happens inside that directory.**
- The repin is already applied and verified there: `Cargo.toml` (`rev` + `version`),
  `Cargo.lock`, `Package.swift`, `SiaStorageSDK.podspec`, `kotlin/gradle.properties`,
  `examples/kotlin/gradle.properties`, `kotlin/README.md`, `examples/kotlin/README.md`,
  and `swift/README.md`. Do not redo this by hand. Do not touch the `checksum:` in
  `Package.swift` — the Swift release job sets it when it publishes the xcframework.
- Rust, Python 3.12, JDK 17, Gradle 8.10.2, and maturin are installed.
- `/tmp/gh-aw/sdk-update.json` — old and new rev/version, the release tag, whether the
  repin actually happened, and why not if it did not.
- `/tmp/gh-aw/ffi.diff` — the diff of `sia_storage_ffi/src` between the old and new revs.
  This is the primary signal for what changed in the FFI surface.
- `/tmp/gh-aw/changelog.md` — changelog heads for `sia_core`, `sia_storage`, `sia_storage_ffi`.
- `/tmp/gh-aw/sia-sdk-rs/` — a full checkout of this repository, for reading the crate
  source directly when the diff is not enough.

If `repinned` is false, read `skip_reason`. Either the pin is already current or the
release would be a downgrade. Nothing was modified; call `noop` and stop.

## Task

1. **Build and regenerate the bindings.** From the repository root:

   ```
   cargo build --release
   cargo run --release --bin uniffi-bindgen -- generate \
     --library target/release/libsia_storage_ffi.so \
     --language swift --out-dir build/generated --config swift/uniffi.toml
   cp build/generated/SiaStorageSDK.swift swift/Sources/SiaStorageSDK/SiaStorageSDK.swift
   cargo run --release --bin uniffi-bindgen -- generate \
     --library target/release/libsia_storage_ffi.so \
     --language kotlin --out-dir kotlin/src/main/kotlin --config kotlin/uniffi.toml --no-format
   ```

   `swift/Sources/SiaStorageSDK/SiaStorageSDK.swift` is generated but committed, so it
   must be regenerated and will show up in the diff. The Kotlin and Python generated
   modules are gitignored — they exist only to build and test against.

2. **Verify Kotlin.**

   ```
   mkdir -p kotlin/src/main/resources/linux-x86-64
   cp target/release/libsia_storage_ffi.so kotlin/src/main/resources/linux-x86-64/
   cd kotlin && gradle test
   ```

3. **Verify Python.** Build and install the wheel into a virtualenv, then import it.
   Skip `--release`; this is an import check, not a benchmark.

   ```
   mkdir -p /tmp/gh-aw/agent
   python -m venv /tmp/gh-aw/agent/venv
   VENV=/tmp/gh-aw/agent/venv
   $VENV/bin/pip install -q maturin
   cd python && $VENV/bin/maturin build --out dist
   $VENV/bin/pip install --force-reinstall dist/*.whl
   $VENV/bin/python -c "import sia_storage; from sia_storage import SDK, Builder, generate_recovery_phrase; print(len(sia_storage.__all__), 'exports')"
   ```

   The import is the real test: `python/sia_storage/__init__.py` re-exports every name
   explicitly, so a renamed or removed FFI type fails at import time.

4. **Fix what broke and extend the wrappers.** Each language has a different rule.
   Extend the existing structure; do not restructure it, and do not add new files.

   - **Python — `python/sia_storage/__init__.py` (required for every new type).** Names
     are invisible to users until listed here. Add each new binding to *both* the
     `from sia_storage.sia_storage.sia_storage_ffi import (...)` block and `__all__`,
     under the matching `# Functions` / `# Classes/Objects` / `# Records` / `# Enums` /
     `# Errors` / `# Base classes ...` comment group. Preserve the existing aliases
     (`SDK = Sdk`, `IOError = IoError`) and the alias comments in `__all__`.
   - **Python — `python/sia_storage/wrappers.py`.** Idiomatic layer over the raw
     bindings. Its top-level import block must stay in sync with what it uses. Extend
     only when a new binding needs the same treatment the existing ones get.
   - **Swift — `swift/Sources/SiaStorageSDK/Wrappers.swift`.** Extensions and
     conveniences only; the generated file already exposes the raw API. Follow the
     existing conventions: `/** ... */` doc comments with a runnable `Example:` block,
     `extension` on the generated type rather than a new wrapper type.
   - **Kotlin — `kotlin/src/main/kotlin/sia/indexd/Wrappers.kt`.** Same shape as Swift:
     KDoc with an `Example:` block, extension functions on the generated types.
   - **Examples.** `examples/python/example.py`, `examples/swift/Sources/main.swift`, and
     `examples/kotlin/src/main/kotlin/Example.kt` must keep compiling against the new
     API. The Swift CI builds `examples/swift`, so a break there fails the pull request.

   Only wrap bindings the crate actually exposes at the new rev. Confirm each against
   `/tmp/gh-aw/sia-sdk-rs/sia_storage_ffi/src` or the regenerated Swift file before
   adding it — do not infer an export from the changelog alone. Keep the three languages
   consistent: a convenience that makes sense in one usually makes sense in all three.
   Never silence a failure by deleting a test, an example, or an export.

5. **Re-run steps 1-3 until Kotlin tests and the Python import both pass.** If you cannot
   get them green, still open the pull request, but say plainly at the top of the body
   what is failing and paste the error.

**Swift cannot be compiled here.** This runner is Linux; building the Swift package needs
the xcframework and a macOS toolchain. Regenerating `SiaStorageSDK.swift` and updating
`Wrappers.swift` is all you can verify — the repository's own `swift.yml` builds and
tests Swift on the pull request. Say so in the body rather than implying Swift passed.

## Output

Emit one `create_pull_request` targeting `SiaFoundation/sia-storage-sdk`. Title it
`update sia_storage_ffi to X.Y.Z` (the `chore: ` prefix is added for you). The body should
cover, in prose:

- the version and rev move, and the upstream changes that motivated it
- what changed in the regenerated bindings, and every wrapper or example you edited
- which checks you actually ran and their result, and that Swift was not compiled
- anything left undone: a binding you could not wrap, or a failing check

Call `noop` with a short explanation instead of opening a pull request when `repinned` is
false, or when the regenerated bindings and all three wrappers come out byte-identical
and every check passes — that is the expected outcome for a release that only changes
crate internals.
