# Versioning and releases

How OpenCTEM is versioned and released. The decisions and their reasons are in
[RFC-037](../rfcs/RFC-037-versioning-and-release-train.md); this page is the
working reference.

## The rule in five lines

1. The platform version is the `vX.Y.Z` tag on `main`. API and web share it.
2. Every component reports `version`, `commit` and `channel`
   (`release` | `rc` | `dev`). Dev builds are `<highest tag>-dev+<sha8>`.
3. No version is hardcoded. Defaults live in `versions.yaml` and are copied
   by `.github/scripts/release/sync-versions.sh`; `web/package.json` stays `0.0.0`.
4. A release train leaves every other Monday; security and critical fixes
   ship at once as patch releases.
5. The version is proposed from conventional commits and confirmed by the
   owner pressing Run.

## versions.yaml

```yaml
platform: { release: v0.8.0 }          # newest released tag (vX.Y.Z on release/vX.Y.Z)
sensor:   { latest: v0.6.4, min: "" }  # install snippets + "update available" / "unsupported"
sdk:      { latest: v0.14.0, min: "" } # "outdated" / "SDK below minimum"
chart:    { version: 0.4.1 }           # newest chart whose appVersion is platform.release
```

(The file itself uses block style; the scripts read two-level `key: value`
lines without a YAML library.)

To change a default: edit `versions.yaml`, run
`.github/scripts/release/sync-versions.sh`, commit both. The **Version
consistency** check (`sync-versions.sh --check`, workflow Release Tooling)
fails a PR whose defaults disagree with the file, whose `web/package.json` is
not `0.0.0`, or whose `platform.release` is newer than any tag. On
`release/vX.Y.Z` (and on `main` right after it merges) it runs with
`--release vX.Y.Z` instead: `platform.release` must be exactly `vX.Y.Z`, so the
tag's checkout (`api/deploy/.env.example`, `docker-compose.yml`) installs its
own version.

| Consumer | Field |
|---|---|
| `api/internal/versions/versions.yaml`: the API's embedded copy, byte for byte (`go:embed` cannot reach outside the `api/` module); every Go default reads it | all |
| `api/deploy/docker-compose.yml`, `docker-compose.job-signer.yml` `OPENCTEM_VERSION` default | platform.release |
| `api/deploy/.env.example` `OPENCTEM_VERSION` | platform.release |
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
   commit, one commit setting `versions.yaml` `platform.release` to `vX.Y.Z`
   synced into every default, and a `merge -s ours` commit recording `main`
   as a parent) and
   opens the PR into `main`, queued for the merge queue. Without
   `RELEASE_TOKEN`, open the PR from the link in the run summary.
4. When the merge queue merges it, **Release Publish** tags `vX.Y.Z` on the
   merge commit (only if `main`'s tree equals the release branch's and its
   `versions.yaml` says `vX.Y.Z`), which
   publishes the images (Docker Publish) and the GitHub Release (notes with
   `@mentions` escaped and emails dropped).
5. Merge the follow-up PRs it opens:
   - `develop`: `main` merged back (the tag becomes reachable; it brings only
     the release branch's version commit, anything else is refused) and
     `versions.yaml` `chart.version` set;
   - `helm-charts`: `appVersion` and the chart version.
6. If the release needs release notes or an upgrade page, write it in
   `openctemio/docs`.

### Hotfix

Merge the fix into `develop`, then run Release Train with `mode: hotfix` and
`cherry_picks: <develop SHA …>`. The release is the last tag's patch + 1,
built from the tag plus the cherry-picks plus the version commit. Its
follow-up only bumps `versions.yaml` on `develop`.

## Scripts

All under `.github/scripts/release/`, tested by `tests/run.sh` (CI: Release
scripts).

| Script | Does |
|---|---|
| `lib.sh` | version rules, bump kinds, `versions.yaml` get/set |
| `next-version.sh` | proposed version, counts, changelog preview |
| `changelog.sh` | grouped Markdown preview (breaking, security, features, fixes, performance, other) |
| `check-ci.sh` | required checks of a commit; newest green commit of a branch |
| `cut-release.sh` | builds `release/vX.Y.Z` (train or hotfix) with its version commit, with the `-s ours` precondition per file |
| `tag-release.sh` | annotated tag after the tree and `platform.release` checks |
| `post-release.sh` | the develop follow-up branch |
| `helm-bump.sh` | chart `appVersion` + version bump |
| `sync-versions.sh` | `versions.yaml` → consumers; `--check` for CI; `--release vX.Y.Z` on a release branch |
| `sanitize-notes.py` | escape `@mentions`, drop emails |

`api/scripts/release-branch.sh` is the older interactive equivalent of
`cut-release.sh`; prefer the workflow.

## Build identity today

- API: `GET /api/v1/version` (signed-in) → `{version, commit, build_time, channel}`,
  from ldflags (release images, `api/.air.toml` in the dev container) or the
  checkout's `.git`.
- Web: `GET /api/version` (signed-in), from `NEXT_PUBLIC_APP_VERSION` or `.git`.
- `/health` carries no version, on purpose.
