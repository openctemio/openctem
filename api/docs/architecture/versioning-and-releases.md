# Versioning and releases

How OpenCTEM is versioned and released. The decisions and their reasons are in
[RFC-037](../rfcs/RFC-037-versioning-and-release-train.md); this page is the
working reference.

## The rule in five lines

1. The platform version is the `vX.Y.Z` tag on `main`. API and web share it.
2. Every component reports `version`, `commit` and `channel`
   (`release` | `rc` | `dev`). Dev builds are `<highest tag>-dev+<sha8>`.
3. No version of the platform is committed on `develop`. The tag is the only
   source: images and binaries take it from the build (ldflags), a tag's
   checkout installs it from `api/deploy/VERSION` (written on the release
   branch only). Component defaults (sensor, SDK, CI runner) live in
   `versions.yaml`, copied by `.github/scripts/release/sync-versions.sh`;
   `web/package.json` stays `0.0.0`.
4. A release train leaves every other Monday; security and critical fixes
   ship at once as patch releases.
5. The version is proposed from conventional commits and confirmed by the
   owner pressing Run.

## Where the version comes from

| Place | Source |
|---|---|
| Release images, binaries (`GET /api/v1/version`, `-version`, web `/api/version`) | the tag, passed to the build (`-ldflags`, `NEXT_PUBLIC_APP_VERSION`) |
| Dev builds | `<highest tag>-dev+<sha8>` |
| Compose stack (`api/deploy`) | `OPENCTEM_VERSION` in `.env`, required: the compose files have no default (`${OPENCTEM_VERSION:?...}`). `setup.sh` writes it from `--version`, else `api/deploy/VERSION`, else the exact tag checked out; a branch checkout without `--version` is refused |
| `api/deploy/VERSION` | one line `vX.Y.Z`, written by `cut-release.sh` on `release/vX.Y.Z` only. It reaches `main` and the tag, never `develop` |
| Content catalog compatibility, `content-bundle -platform` default | `versions.PlatformRelease()`: the `vX.Y.Z` core of the running build's version |
| Air-gapped bundles | `@VERSION@` filled by the release build; images pinned by digest |
| Helm chart | `appVersion` in `openctemio/helm-charts`, bumped by the Release Publish follow-up |

So a release is: one commit on the release branch (the `VERSION` file), the
tag, and (trains only) a merge of `main` back into `develop` with `-s ours`
that makes the tag reachable and changes no file. Nothing about the version is
committed to `develop`, so no per-release "bump" PR exists.

## versions.yaml

```yaml
sensor:   { latest: v0.6.4, min: "" }  # install snippets + "update available" / "unsupported"
sdk:      { latest: v0.14.0, min: "" } # "outdated" / "SDK below minimum"
ci:       { latest: v0.3.0, min: "" }  # the console's CI pipeline snippets
```

(The file itself uses block style; the scripts read two-level `key: value`
lines without a YAML library.) It holds the compatibility floors and the
built-in "latest" of the components that release on their own lines. It has no
`platform` or `chart` section (the check refuses them).

To change a default: edit `versions.yaml`, run
`.github/scripts/release/sync-versions.sh`, commit both. The **Version
consistency** check (`sync-versions.sh --check`, workflow Release Tooling)
fails a PR whose defaults disagree with the file, whose `web/package.json` is
not `0.0.0`, or whose `api/deploy/VERSION` names a version newer than any tag.
On `release/vX.Y.Z` (and on `main` right after it merges) it runs with
`--release vX.Y.Z` instead: `api/deploy/VERSION` must be exactly `vX.Y.Z`.

| Consumer | Field |
|---|---|
| `api/internal/versions/versions.yaml`: the API's embedded copy, byte for byte (`go:embed` cannot reach outside the `api/` module); every Go default reads it | all |
| `api/deploy/docker-compose.sensor.yml` `SENSOR_VERSION` default | sensor.latest |
| `web/src/features/ci-runners/lib/ci.ts` `CI_RELEASE` | ci.latest |

No Go file holds a version, so bumping a sensor product, the SDK or the CI
runner changes `versions.yaml` and its embedded copy only (a shell test runs
the bump on a fixture and checks the changed files).

## Proposed version

`next-version.sh` reads the commits on `develop` that are not reachable from
the last tag (nor from `ui/<last tag>`, the imported web history):

| Strongest change | Before 1.0.0 | From 1.0.0 |
|---|---|---|
| `type!:` subject or `BREAKING CHANGE:` footer | minor | major |
| `feat` | minor | minor |
| anything else | patch | patch |

"Last tag" is the highest `vX.Y.Z` by version sort, never `git describe`.

## Running a release

1. On a train Monday, the issue **Release train vX.Y.Z** (label
   `release-train`) shows the proposal, the develop commit the train would
   take and a changelog preview.
2. **Actions › Release Train › Run workflow.** Until a release has brought
   the workflow to `main`, choose "Use workflow from: develop".
   - `dry_run` (default on): plan only. The run summary shows the version,
     the commit and the changelog; the release branch is built locally to
     prove it can be.
   - `version`: override the proposal (must be greater than the last tag).
   - `sha`: release a specific develop commit (its required checks must be
     green).
3. With `dry_run` off, the workflow pushes `release/vX.Y.Z` (the develop
   commit, one commit writing `api/deploy/VERSION` = `vX.Y.Z`, and a
   `merge -s ours` commit recording `main` as a parent) and
   opens the PR into `main`, queued for the merge queue. Without
   `RELEASE_TOKEN`, open the PR from the link in the run summary.
4. When the merge queue merges it, **Release Publish** tags `vX.Y.Z` on the
   merge commit (only if `main`'s tree equals the release branch's and its
   `api/deploy/VERSION` says `vX.Y.Z`), which
   publishes the images (Docker Publish) and the GitHub Release (notes with
   `@mentions` escaped and emails dropped).
5. Merge the follow-up PRs it opens:
   - `develop` (trains only): `main` merged back with `-s ours` (the tag
     becomes reachable; no file changes, and a file `main` has that `develop`
     never had is refused). Merge it with the queue, never squash;
   - `helm-charts`: `appVersion` and the chart version.
6. If the release needs release notes or an upgrade page, write it in
   `openctemio/docs`.

### Hotfix

Merge the fix into `develop`, then run Release Train with `mode: hotfix` and
`cherry_picks: <develop SHA …>`. The release is the last tag's patch + 1,
built from the tag plus the cherry-picks plus the version commit. It has no
develop follow-up.

## Scripts

All under `.github/scripts/release/`, tested by `tests/run.sh` (CI: Release
scripts).

| Script | Does |
|---|---|
| `lib.sh` | version rules, bump kinds, `versions.yaml` get/set, the `VERSION` file path |
| `next-version.sh` | proposed version, counts, changelog preview |
| `changelog.sh` | grouped Markdown preview (breaking, security, features, fixes, performance, other) |
| `check-ci.sh` | required checks of a commit; newest green commit of a branch |
| `cut-release.sh` | builds `release/vX.Y.Z` (train or hotfix) with its `api/deploy/VERSION` commit, with the `-s ours` precondition per file |
| `tag-release.sh` | annotated tag after the tree and `api/deploy/VERSION` checks |
| `post-release.sh` | the develop follow-up branch (train: `main` merged back with `-s ours`; hotfix: none) |
| `helm-bump.sh` | chart `appVersion` + version bump |
| `sync-versions.sh` | `versions.yaml` → consumers; `--check` for CI; `--release vX.Y.Z` on a release branch (checks `api/deploy/VERSION`) |
| `sanitize-notes.py` | escape `@mentions`, drop emails |

`api/scripts/release-branch.sh` is the older interactive equivalent of
`cut-release.sh`; prefer the workflow.

## Build identity today

- API: `GET /api/v1/version` (signed-in) → `{version, commit, build_time, channel}`,
  from ldflags (release images, `api/.air.toml` in the dev container) or the
  checkout's `.git`.
- Web: `GET /api/version` (signed-in), from `NEXT_PUBLIC_APP_VERSION` or `.git`.
- `/health` carries no version, on purpose.
