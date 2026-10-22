---
emoji: 🎯
name: Update sia_storage_dart
description: On a sia_storage release, open a pull request in SiaFoundation/sia_storage_dart that updates the Rust dependencies, adapts the Dart API, regenerates flutter_rust_bridge bindings, and verifies native tests and the web build.
on:
  bots: ["sia-ci-bot[bot]"]
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      release_tag:
        description: "sia_storage tag to update to. Defaults to the newest stable release."
        required: false
        type: string
if: github.event_name != 'release' || startsWith(github.event.release.tag_name, 'sia_storage/v')
permissions:
  contents: read
  copilot-requests: write
model: opus
models:
  default-ai-credits-pricing:
    input: 5.0
    output: 25.0
concurrency:
  group: >-
    ${{ (github.event_name != 'release'
    || startsWith(github.event.release.tag_name, 'sia_storage/v'))
    && 'update-sia-storage-dart'
    || format('update-sia-storage-dart-{0}', github.run_id) }}
  cancel-in-progress: true
runs-on: ubuntu-latest
timeout-minutes: 90
network:
  allowed:
    - defaults
    - github
    - rust
    - linux-distros
    - dart
    - rustwasm.github.io
tools:
  bash: ["*"]
  edit:
checkout:
  - repository: SiaFoundation/sia_storage_dart
    ref: main
    path: sia_storage_dart
steps:
  - name: Setup Dart
    uses: dart-lang/setup-dart@65eb853c7ba17dde3be364c3d2858773e7144260 # v1.7.2
  - name: Setup Rust
    working-directory: sia_storage_dart
    run: |
      set -euo pipefail
      rustup update stable
      rustup toolchain install nightly --component rust-src
      rustup target add wasm32-unknown-unknown --toolchain nightly
      toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust/rust-toolchain.toml)
      : "${toolchain:?Could not read the Rust toolchain}"
      rustup toolchain install "$toolchain" --profile minimal --component rustfmt
      cargo install wasm-pack --locked
  - name: Update Rust dependencies and prepare context
    working-directory: sia_storage_dart
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      RELEASE_TAG: ${{ github.event.release.tag_name || inputs.release_tag }}
      UPSTREAM_REPO: SiaFoundation/sia-sdk-rs
      TAG_PREFIX: sia_storage/v
    run: |
      set -euo pipefail
      mkdir -p /tmp/gh-aw

      # The nested checkout must not be treated as part of the upstream workspace.
      if [ -f "$GITHUB_WORKSPACE/Cargo.toml" ]; then
        mv "$GITHUB_WORKSPACE/Cargo.toml" "$RUNNER_TEMP/sia-sdk-rs-root-Cargo.toml"
      fi

      tag="${RELEASE_TAG:-}"
      if [ -z "$tag" ]; then
        tag=$(gh release list --repo "$UPSTREAM_REPO" --limit 100 \
          --exclude-drafts --exclude-pre-releases --json tagName --jq '.[].tagName' \
          | grep "^$TAG_PREFIX" | sort -V | tail -n1)
      fi
      [[ "$tag" =~ ^sia_storage/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo "Expected a stable sia_storage/vX.Y.Z release, got: $tag" >&2
        exit 1
      }
      export TARGET_TAG="$tag"
      git clone --filter=blob:none "https://github.com/$UPSTREAM_REPO.git" /tmp/gh-aw/sia-sdk-rs

      python3 - <<'PY'
      import json
      import os
      from pathlib import Path
      import re
      import subprocess
      import tomllib

      upstream = "/tmp/gh-aw/sia-sdk-rs"
      tag = os.environ["TARGET_TAG"]
      version = tag.removeprefix("sia_storage/v")
      rev = subprocess.check_output(
          ["git", "-C", upstream, "rev-parse", f"{tag}^{{commit}}"], text=True
      ).strip()
      manifest = tomllib.loads(subprocess.check_output(
          ["git", "-C", upstream, "show", f"{rev}:sia_storage/Cargo.toml"], text=True
      ))
      if manifest["package"]["version"] != version:
          raise SystemExit("Release tag does not match sia_storage's crate version")
      core = manifest["dependencies"]["sia_core"]
      core_version = core if isinstance(core, str) else core["version"]
      lock = tomllib.loads(Path("rust/Cargo.lock").read_text())
      current = [p["version"] for p in lock["package"] if p["name"] == "sia_storage"]
      if len(current) != 1:
          raise SystemExit("Expected exactly one sia_storage version in rust/Cargo.lock")
      current_version = current[0]
      def stable_version(value):
          if not re.fullmatch(r"\d+\.\d+\.\d+", value):
              raise SystemExit(f"Expected a stable version, got: {value}")
          return tuple(map(int, value.split(".")))
      downgrade = stable_version(current_version) > stable_version(version)
      changed = current_version != version and not downgrade
      reason = "refusing to downgrade" if downgrade else "already current" if not changed else ""
      if changed:
          path = Path("rust/Cargo.toml")
          source = path.read_text()
          for crate, requirement in (("sia_storage", version), ("sia_core", core_version)):
              source, count = re.subn(
                  rf'^{crate} = "[^"\n]+"$',
                  f'{crate} = "{requirement}"', source, flags=re.MULTILINE
              )
              if count != 1:
                  raise SystemExit(f"Expected one simple {crate} dependency in rust/Cargo.toml")
          path.write_text(source)
      context = {
          "current": {"version": current_version},
          "target": {"version": version, "rev": rev, "tag": tag, "sia_core": core_version},
          "updated": changed,
          "skip_reason": reason,
      }
      Path("/tmp/gh-aw/sdk-update.json").write_text(json.dumps(context, indent=2) + "\n")
      print(json.dumps(context, indent=2))
      old_tag = f"sia_storage/v{current_version}"
      diff = subprocess.check_output(
          ["git", "-C", upstream, "diff", f"{old_tag}..{rev}", "--", "sia_storage/src", "sia_core/src"]
      )
      Path("/tmp/gh-aw/sdk.diff").write_bytes(diff[:400000])
      with Path("/tmp/gh-aw/changelog.md").open("w") as output:
          for crate in ("sia_core", "sia_storage"):
              result = subprocess.run(
                  ["git", "-C", upstream, "show", f"{rev}:{crate}/CHANGELOG.md"],
                  text=True, capture_output=True, check=True
              )
              output.write(f"## {crate}\n" + "\n".join(result.stdout.splitlines()[:60]) + "\n\n")
      subprocess.run(["git", "-C", upstream, "checkout", "--detach", rev], check=True)
      PY
safe-outputs:
  github-app:
    client-id: ${{ secrets.SIA_CI_BOT_APP_ID }}
    private-key: ${{ secrets.SIA_CI_BOT_PRIVATE_KEY }}
    owner: SiaFoundation
    repositories: [sia_storage_dart]
  create-pull-request:
    target-repo: SiaFoundation/sia_storage_dart
    title-prefix: "chore: "
    labels: [dependencies]
    draft: false
    allowed-files:
      - ".changeset/**"
      - "rust/Cargo.toml"
      - "rust/Cargo.lock"
      - "rust/rust-toolchain.toml"
      - "rust/src/**"
      - "lib/**"
      - "test/**"
      - "example/**"
      - "hook/**"
      - "tool/**"
      - "flutter_rust_bridge.yaml"
      - "pubspec.yaml"
      - "README.md"
    protected-files:
      policy: request_review
      exclude: [".changeset/", "README.md"]
---

# Update sia_storage_dart for a new sia_storage release

`SiaFoundation/sia_storage_dart` wraps `sia_storage` directly with a Rust adapter
and flutter_rust_bridge-generated Dart bindings. It does not use `sia_storage_ffi`.
Update the existing API to match the released core SDK, preserving its Dart conventions.

## What is already set up

- `sia_storage_dart/` is a checkout of `SiaFoundation/sia_storage_dart` (branch `main`).
  **Every command and edit below happens inside that directory.**
- `rust/Cargo.toml` has the target `sia_storage` version and the corresponding
  `sia_core` requirement. The lockfile still needs to be updated. Package versions in
  `pubspec.yaml` and `rust/Cargo.toml` are independent of the upstream crate version;
  leave those versions and the release-managed changelog alone.
- Dart, stable Rust, the repository's pinned Rust toolchain with rustfmt, nightly
  with rust-src and the wasm target, and wasm-pack are installed.
- The upstream workspace's root `Cargo.toml` has been moved aside so Cargo accepts
  the nested target checkout. Do not restore it or build from the upstream root.
- `/tmp/gh-aw/sdk-update.json` contains the old and target versions and skip reason.
- `/tmp/gh-aw/sdk.diff` contains the changes to `sia_storage/src` and `sia_core/src`.
- `/tmp/gh-aw/changelog.md` contains the released crates' changelog heads.
- `/tmp/gh-aw/sia-sdk-rs/` is checked out at the target release for reading core APIs.

If `skip_reason` is `refusing to downgrade`, call `noop` and stop. If the version is
already current, continue checking bindings and wrappers: an earlier dependency bump
may have left API updates outstanding.

## Task

1. **Resolve dependencies.** From `rust/`, run `cargo update --package sia_storage
   --precise X.Y.Z`, substituting the target version from the context. Verify with
   `cargo metadata --format-version 1` that the resolved `sia_storage` version matches
   the target. Keep the direct `sia_core` requirement compatible with the version used
   by `sia_storage`; do not introduce duplicate incompatible core types. Run
   `dart pub get` from the package root. Only change other dependency constraints or
   the pinned Rust toolchain if the release requires it, and explain why in the PR.

2. **Adapt the Rust API.** Inspect the core diff and repair `rust/src/api/` for changed
   signatures, types, and behavior. Expose new public capabilities using the existing
   adapter structure. The released `sia_storage` API is the source of truth; compare
   parameters, defaults, return types, ownership, async behavior, and errors. Preserve
   the existing streaming callbacks and native/web adaptations. Do not invent new
   abstractions or refactor unrelated code.

3. **Regenerate the bindings.** Read the exact `flutter_rust_bridge` version from
   `rust/Cargo.toml`, install matching `flutter_rust_bridge_codegen` with
   `cargo install flutter_rust_bridge_codegen --version VERSION --locked`, then run
   `flutter_rust_bridge_codegen generate` from the package root. Keep it compatible
   with the runtime in `pubspec.yaml` and `FRB_VERSION` in `tool/build_web.sh`.
   Never hand-edit generated files in `lib/src/rust/` or `rust/src/frb_generated.rs`.
   Commit all regenerated Dart and Rust bindings together.

4. **Update the public Dart API.** Extend the explicit exports and hand-written
   wrappers in `lib/sia_storage.dart`. Preserve `Sia`'s automatic initialization,
   const option classes, and the stream helpers for `Sdk` and `PackedUpload`.
   Confirm each exported binding against the regenerated API. Keep
   `example/sia_storage_example.dart`, relevant README examples, and tests in sync.
   Add focused tests for changed behavior where practical; never delete tests or
   exports merely to make checks pass.

5. **Build and verify.** Run from the package root:

   ```
   dart pub get
   (cd rust && cargo test)
   dart analyze
   dart test
   tool/build_web.sh
   dart analyze
   dart test
   ```

   The web script regenerates bindings before building the threaded WASM bundle.
   Rechecking Dart afterward ensures the committed bindings match that final codegen
   pass. Keep `web/pkg/` and build/cache output gitignored; the publishing workflow
   builds the bundle. Check formatting of changed hand-written Rust and Dart files
   without formatting unrelated code. Fix failures and rerun affected checks. If a
   check cannot pass, still open the PR with the error prominently at the top.
   A successful web build is not a browser runtime test; say which platforms were
   actually tested. Flutter consumer dependency resolution is checked by the target
   repository's CI; do not claim that check passed locally.

6. **Write a changeset for each user-facing change in the upstream release.**
   Use the SDK changesets consumed by the release as the source of truth for both
   the description and each change's `major`, `minor`, or `patch` classification.
   Cover every release between the old and target pins in `/tmp/gh-aw/sdk-update.json`,
   using each crate's own pin range when they differ. Read the released changelog
   entries in `/tmp/gh-aw/sia-sdk-rs/` and recover the original `.changeset/` files and
   frontmatter from git history before the release consumed them. Do not use
   unreleased changesets or infer the classification from the overall version bump.
   `/tmp/gh-aw/changelog.md` is only a preview; read the full release entries.

   For each upstream change that reaches this wrapper's users, create a separate
   `.changeset/<release>-<change>.md`. Preserve the upstream change's classification
   for the relevant crate, map its package keys to the target repository's package
   keys, and adapt the wording only for the exposed language APIs and supported
   platforms. Use the target repository's changeset format (`default` as the package
   key if no existing convention is available). Include inherited fixes and security
   updates even when no wrapper code changes. Deduplicate the same change appearing
   in multiple crate changelogs, and omit changes that do not affect this wrapper.
   Explain omissions or any classification adjustment in the PR body. If the original
   classification cannot be recovered, report that explicitly instead of silently
   defaulting to `patch`.

   Do not replace these entries with a generic dependency-update changeset. Preserve
   unrelated existing changesets. If an automated pin bump already created a generic
   `.changeset/sdk-update.md` for this release, replace that entry with the individual
   release-derived entries; reuse any matching entries that already exist. Changeset
   files are an exception to the rule against adding new files. Describe any additional
   user-facing wrapper changes separately: `major` for breaking changes, `minor` for
   backward-compatible additions, and `patch` for backward-compatible fixes. Leave
   package versioning to the existing release process.

7. **Check scope.** Run `git status` and `git diff --check`. Keep only changes under
   the allowed paths above. Do not change `.github/` workflows or release configuration.
   Describe any required changes outside the allowed paths in the PR body.

## Output

Emit one `create_pull_request` targeting `SiaFoundation/sia_storage_dart`, titled
`update sia_storage to X.Y.Z` (the `chore: ` prefix is added for you). Describe the
version move, Rust adapter and Dart API changes, regenerated bindings, checks actually
run and their results, and anything incomplete or requiring follow-up.

Call `noop` only for a downgrade or when there is no remaining diff and all applicable
checks pass. A dependency or lockfile update still needs a PR even if the generated
bindings are unchanged.
