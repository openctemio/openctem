# RFC-037 — Versioning rule and release train

> Status: **Accepted** (decisions 2026-10-02, §8; design PR #787). P0–P2 are
> implemented in this repository (`versions.yaml`, the Release Train, Release
> Publish and Release Reminder workflows, the version/commit/channel triple in
> `pkg/version`); P3 and P4 belong to the sdk-go, sensor and helm-charts
> repositories (§9). The sensor product catalog (§11) is implemented: the API
> embeds `versions.yaml`, and each sensor product has its own release line.
> Sensor and SDK releases without a platform release (§12) are implemented:
> the release feed carries the first-party component releases and a running
> instance learns them. Product-agnostic compatibility, the SDK minimum and
> organizations' own products (§13) are implemented.
> Scope: `openctemio/openctem` (api + web), `openctemio/sdk-go`,
> `openctemio/sensor`, `openctemio/helm-charts`, `openctemio/docs`.
>
> Goal (2026-10-02): one versioning rule for the whole project, a
> fixed release cadence, and version numbers the tooling proposes instead of
> people remembering them.

## 1. Answer in short

- **One version per product, from one place.** The platform (API and web) is
  versioned by the `vX.Y.Z` tag on `main` of `openctemio/openctem`. Nothing
  else names the platform version: no `package.json` version, no hardcoded
  defaults, no `git describe`.
- **Every component says what it is** with the same triple:
  `version`, `commit`, `channel` (`release`, `rc` or `dev`). A development
  build reports `<highest tag>-dev+<sha>`, computed by sorting tags.
- **One compatibility manifest**, `versions.yaml` at the repository root,
  holds every version default the platform ships with (sensor and SDK latest
  and minimum, the platform release, the chart). Go defaults, compose
  defaults and `.env` examples are copies, rewritten by a script and checked
  by CI.
- **A release train every other Monday**, plus immediate patch releases for
  security and critical fixes. A scheduled workflow opens an issue with the
  proposed version and changelog; a maintainer presses **Run**; automation cuts
  the release branch, merges it, tags, publishes and opens the follow-up PRs.
- **The version number is proposed from conventional commits** since the last
  tag (before 1.0.0: breaking or feat → minor, anything else → patch). A
  maintainer can override it when pressing Run.
- `sdk-go` and `sensor` follow the same rule with their own tags.

## 2. Current state (verified 2026-10-02 on `develop` f495f373)

| Area | Finding |
|---|---|
| Tags | Newest platform tag `v0.8.0` (2026-09-30), on `main`. `develop` does not descend from it (release PRs were squashed, and release branches carry `main` only as a second parent), so `git describe` on `develop` answers `v0.2.1-2374-g…`. |
| Unreleased work | 482 non-merge commits on `develop` since `v0.8.0` (excluding the imported web history before `ui/v0.8.0`), one of them breaking. Releases happen when someone remembers. |
| API identity | Release images: `-ldflags -X …/pkg/version.{Version,Commit,BuildTime}` (`api/Dockerfile`). Dev container: `api/.air.toml` stamps `<highest tag>-dev`; a binary without ldflags reads `.git` itself (`pkg/version/gitinfo.go`). Channels: `release` and `development`. `GET /api/v1/version` and `/api/v1/admin/version` require a session. `/health` carries no version, on purpose (no anonymous fingerprinting). |
| Web identity | `NEXT_PUBLIC_APP_VERSION` / `NEXT_PUBLIC_APP_COMMIT` in release images; otherwise `/api/version` reads `.git` (`web/src/lib/version/`). `web/package.json` said `0.2.0`, read by nothing and never bumped. |
| Version defaults | The built-in sensor release was `v0.4.2` in five places (Go default, install-snippet image, compose default, `.env.example`, a test) while the newest published sensor is `v0.6.4`: every install snippet pinned a sensor three releases old. The SDK "latest" default was off in Go and compose and `v0.9.0` in `.env.example`; the newest SDK is `v0.14.0`. |
| Helm chart | Charts 0.5.0 to 0.10.0 default to `appVersion: v0.9.0` and the image repositories `ghcr.io/openctemio/openctem-api` / `openctem-web`. Neither the tag nor those repositories exist yet (GHCR has `api`, `ui` and `migrations` up to `v0.8.0`), so a default install pulls images that do not exist. Chart 0.4.1 is the newest chart for `v0.8.0`; 0.5.0 renamed agents to sensors and needs the v0.9.0 API. |
| Release mechanics | Images and GitHub Releases are published only by a pushed `v*` tag (`docker-publish.yml`, `release.yml`). `api/scripts/release-branch.sh` builds `release/vX.Y.Z` as develop's tree plus a `merge -s ours origin/main`, so the release PR merges cleanly whatever button is pressed. `main` and `develop` now merge through a merge queue with the MERGE method. |
| Release precondition | `release-branch.sh` refuses when a file exists on `main` but not on `develop`. Today five such files exist, all deleted on `develop` on purpose on 2026-10-02 (the token-leaking `sse-token` route and dead hooks): the next cut would be refused for no reason. |
| sdk-go | `pkg/sdk/version.go` `const Version` plus `CHANGELOG.md`; `TestVersionNotBehindChangelog` keeps them together. A release PR bumps both, then the tag is pushed by hand. Dev builds report `<Version>-devel`. |
| sensor | `main.Version` defaults to `v0.1.0` and `make` stamps `git describe` output. `CHANGELOG.md` has an `[Unreleased]` section that a release folds by hand. |

## 3. The rule

### 3.1 Source of truth

| Product | Version source | Shape |
|---|---|---|
| Platform (API + web, one image set) | annotated tag on `main` of `openctemio/openctem` | `vX.Y.Z` |
| SDK | tag on `main` of `openctemio/sdk-go`, mirrored in `pkg/sdk.Version` (no `v`) | `vX.Y.Z` |
| Sensor | tag on `main` of `openctemio/sensor` | `vX.Y.Z` |
| Helm chart | `version` in `Chart.yaml` (SemVer without `v`); `appVersion` = the platform tag it deploys | `X.Y.Z` / `vX.Y.Z` |

`ui/vX.Y.Z` tags are the imported history of the archived `openctemio/ui`.
They never count: the scripts only consider tags matching
`^v[0-9]+\.[0-9]+\.[0-9]+$`.

### 3.2 Build identity: version, commit, channel

Every component reports the same triple wherever it reports a version:

| Build | `version` | `commit` | `channel` |
|---|---|---|---|
| Release tag `v0.9.0` | `v0.9.0` | short SHA (8) | `release` |
| Pre-release tag `v0.9.0-rc.1` (or any other pre-release suffix except `-dev`) | `v0.9.0-rc.1` | short SHA | `rc` |
| Anything else (dev container, local build, CI build of a branch) | `v0.8.0-dev+4d2f4b02` | short SHA | `dev` |

Where it is reported:

- API: `GET /api/v1/version` and `/api/v1/admin/version` (signed-in only).
- Web: `GET /api/version` (signed-in only); Help > About shows both.
- Sensor: `-version`, the heartbeat `version`, the User-Agent.
- SDK: the User-Agent and the heartbeat `sdk` member (from the Go build info).

`/health` stays minimal and public: `{"status": …}` only. Publishing the exact
build to anonymous callers helps an attacker match it to known CVEs and helps
nobody else (decision O5, §8).

### 3.3 Development builds

A dev build's version is `<base>-dev+<sha8>`, where `<base>` is **the highest
`vX.Y.Z` tag in the repository by version sort**. Never `git describe`: tags
live on `main` and release branches, so on `develop` describe finds whichever
old tag happens to be an ancestor.

The base is the highest existing tag, not the next proposed version (decision
O6): every reader can compute it from tags alone, including the API's
`.git` reader that runs without a `git` binary, and it does not change from
commit to commit while the proposal does. SemVer orders `v0.8.0-dev` before
`v0.8.0`; nothing compares dev builds by version (the Sensors page treats a
non-release version as "unknown"), and the channel says what it is.

A checkout only knows the tags it fetched. A tag on `main` is not reachable
from `develop`, so `git pull` alone does not fetch it: the release workflow
merges `main` back into `develop` after each train (§4.2), and long-lived dev
checkouts should set `git config remote.origin.tagOpt --tags`.

### 3.4 No hardcoded versions

- A version string appears in the source only as (a) a release tag, (b) a
  copy of `versions.yaml` written by `sync-versions.sh`, or (c) test data.
  No Go file holds one: the API reads every version default from its
  embedded copy of `versions.yaml` (§11).
- `web/package.json` is `"version": "0.0.0"` permanently. npm requires the
  field to be valid SemVer; the web app's version comes from the build.
- Release builds get the version from the tag (`--build-arg VERSION`,
  ldflags, `NEXT_PUBLIC_APP_VERSION`), never from a file in the tree.

### 3.5 The compatibility manifest

```yaml
# versions.yaml (repository root)
platform:
  release: v0.8.0   # newest released tag; on release/vX.Y.Z: vX.Y.Z (set by the cut)
sensor:             # one section per sensor product (§11)
  product: openctemio-sensor
  latest: v0.6.4    # install snippets pin it; older sensors show "update available"
  min: ""           # older sensors are degraded "version unsupported"; "" = none
  image: ghcr.io/openctemio/sensor
  install: sensor
  release_identity: https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml
sdk:
  latest: v0.14.0   # sensors built with an older SDK are "outdated" (informational)
  advisories: ""    # SDK releases with a security advisory: a warning; "" = none
ci:
  latest: v0.3.0
  min: v0.3.0
chart:
  version: 0.4.1    # newest published chart whose appVersion is platform.release
```

`.github/scripts/release/sync-versions.sh` copies it into its consumers: the
API's embedded copy `api/internal/versions/versions.yaml` (whole file),
`OPENCTEM_VERSION` in `api/deploy/.env.example` and the compose files, and the
console's CI runner pin. The consumer table in the script is the only place a
versioned default may live. With `--check` it is the **Version consistency**
CI job, which also fails when `web/package.json` is not `0.0.0` or when
`platform.release` names a tag that does not exist. The one exception is the
release branch: on `release/vX.Y.Z` (and on `main` right after it merges, before
the tag exists) the job runs with `--release vX.Y.Z`, and `platform.release`
must be exactly `vX.Y.Z`. A tag's checkout therefore defaults to its own
version: `api/deploy/.env.example` and `docker-compose.yml` on `v0.9.0` install
`v0.9.0`, not the release before it.

Who bumps what:

| Field | Bumped by |
|---|---|
| `platform.release` | the platform release workflow: one commit on the release branch (`cut-release.sh`); `develop` gets it when `main` is merged back (a hotfix: the post-release PR sets it) |
| `sensor.latest` | the sensor release workflow, in a PR to `openctemio/openctem` after it tags |
| `<product>.latest` of another product | its release workflow the same way, or a person (YAML only) |
| `sdk.latest` | the sdk-go release workflow, same way |
| `sdk.advisories` | a person, when an SDK security advisory is published |
| `*.min` | a person, deliberately: raising a minimum degrades fleets |
| `chart.version` | the platform release workflow, in the post-release PR to `develop`, together with the helm-charts PR it opens (the chart is published after the tag, so a tag names the previous chart) |

The Helm chart repository keeps its own `values.yaml` defaults; its CI checks
that `appVersion` names a published platform tag (§9, P4).

### 3.6 The version number

The release workflow proposes the next version from the commits on `develop`
that are not reachable from the last tag (nor from `ui/<last tag>`, which
excludes the imported web history once):

| Commits since the last tag contain | Before 1.0.0 | From 1.0.0 |
|---|---|---|
| `type!:` / `type(scope)!:` subject, or a `BREAKING CHANGE:` footer | minor | major |
| a `feat` | minor | minor |
| only other types (`fix`, `perf`, `deps`, `docs`, …, non-conventional) | patch | patch |
| nothing | no release | no release |

A maintainer can override the proposal with any version greater than the last
tag. `v1.0.0` is only ever reached by an explicit override.

## 4. Release train

### 4.1 Cadence

- **Every other Monday**, counted from the anchor Monday in the repository
  variable `RELEASE_TRAIN_ANCHOR` (default `2026-10-05`). The reminder runs at
  01:00 UTC.
- **Immediately**, as a patch release (hotfix), for a security fix or a
  critical bug (§4.3). It does not move the train.
- No freeze: `develop` is releasable by policy (every PR passes the merge
  queue). The train takes the newest `develop` commit whose required checks
  are green.

### 4.2 Flow

```
Monday 01:00 UTC  Release Reminder (schedule, train weeks only)
                   └─ opens/updates issue "Release train vX.Y.Z": proposed version,
                      why, the green develop SHA, changelog preview, checklist
Maintainer         Actions › Release Train › Run  (dry_run: true first, if wanted)
Release Train      plan   last tag → proposed version (or the override, validated)
                          newest develop commit with every required check green
                          (or the given SHA, which must be green)
                          changelog preview → run summary
                   cut    release/vX.Y.Z = that SHA
                          + version commit (versions.yaml platform.release = vX.Y.Z, synced)
                          + `merge -s ours origin/main`
                          (tree == develop's + the version commit, main recorded as a parent)
                          PR release/vX.Y.Z → main, queued for merge (MERGE)
Merge queue        required checks on the merge group → merge into main
Release Publish    (on that PR's merge) verify main's tree == the release branch's
                   and its versions.yaml says vX.Y.Z,
                   annotated tag vX.Y.Z on the merge commit
                   → Docker Publish + Release (images, GitHub Release, notes
                     with @mentions escaped and emails dropped)
                   follow-ups:
                   - PR to develop: merge main back (tags become reachable; it
                     brings only the version commit, else refused),
                     versions.yaml chart.version (+ sync)
                   - PR to helm-charts: appVersion vX.Y.Z, chart version bump
                   - docs: release notes / upgrade page stay a person's job
```

The release branch precondition is refined: a file on `main` that is missing
on `develop` blocks the cut only if `develop` never deleted it. A deliberate
deletion on `develop` is what the release ships; a file only `main` ever had
is a hotfix that would be lost, and the cut is refused.

### 4.3 Hotfix (patch) releases

For a security or critical fix that cannot wait for the train:

1. Merge the fix into `develop` as usual (it then ships with the next train
   too).
2. Run **Release Train** with `mode: hotfix` and `cherry_picks: <sha> …`
   (the `develop` commits). The version is the last tag's patch + 1.
3. The workflow builds `release/vX.Y.Z` from the last tag, cherry-picks the
   commits (`-x`), adds the version commit, and continues as in §4.2. The
   post-release PR to `develop` only bumps `versions.yaml`; it does not merge
   `main` back (the fix is already on `develop`).

### 4.4 Gates

- Every required check (`API CI OK`, `Web CI OK`, `CodeQL OK`,
  `All-in-one OK`, `Secret Scanning`, `Workflow Lint`) is `success` on the
  chosen `develop` commit; a cancelled or missing check counts as red.
- The version is a `vX.Y.Z` greater than the last tag, and the tag and the
  release branch do not exist yet.
- The release branch's tree equals the chosen commit's tree plus the version
  commit (train), `main`'s tree after the merge equals the release branch's,
  and its `versions.yaml` says `platform.release: vX.Y.Z`; otherwise no tag is
  pushed.
- Dry run (`dry_run: true`, the default) computes and reports everything and
  pushes nothing.

### 4.5 Release candidates

The `rc` channel is defined now so components report it correctly. Cutting
`vX.Y.Z-rc.N` tags is not part of the train yet: `docker-publish.yml` tags
every non-staging release `latest`, which an rc must not get (P4).

## 5. Who does what

| Step | Maintainer | Automation |
|---|---|---|
| Train reminder, proposed version, changelog | reads the issue | Release Reminder |
| Decide to release, confirm or override the version | presses **Run** | |
| Pick a green commit, cut, open and queue the PR | | Release Train |
| Required checks on the release | | merge queue |
| Tag, images, GitHub Release, notes | | Release Publish, Docker Publish, Release |
| Follow-up PRs (develop, helm-charts) | merges them | opened by Release Publish |
| Release notes page / upgrade guide in `openctemio/docs` | writes when a release needs one | |
| Raise a `min` in `versions.yaml` | decides | |
| Hotfix | merges the fix, presses Run with `mode: hotfix` | the rest |

## 6. sdk-go and sensor

Same rule, own tags, no merge queue (both ship from `main`):

- **Release** workflow (dispatch): proposes the version from conventional
  commits since the last tag (same script logic), then opens a release PR
  `release/vX.Y.Z → main` that folds the changelog's Unreleased section into
  `## vX.Y.Z — <date>` (sdk-go also bumps `pkg/sdk.Version`).
- **Release Tag** workflow: when that PR merges, tags the merge commit. The
  tag then runs the existing publish workflows.
- sdk-go: after tagging, opens `deps: sdk-go vX.Y.Z` in `openctemio/sensor`
  (needs `RELEASE_TOKEN`; Dependabot proposes the same bump weekly without it).
- Neither opens anything in `openctemio/openctem`: the platform learns their
  releases from its release feed (§12).
- sensor: dev builds report `<highest tag>-dev+<sha>` (Makefile), never
  `git describe`; the compiled-in default is `dev`, not a release number.
- Releases already in flight when this lands (sdk-go v0.15.0, sensor v0.7.0)
  finish the manual way.

## 7. Tokens and settings (maintainer actions)

| Setting | Why |
|---|---|
| Secret `RELEASE_TOKEN`: a fine-grained personal access token (or GitHub App token) for `openctemio/openctem`, `helm-charts`, `sensor`, `sdk-go` with **Contents: read/write**, **Pull requests: read/write**, **Workflows: read/write** | Branches, PRs and tags pushed with the built-in `GITHUB_TOKEN` do not start other workflows: the release PR would get no required checks and the tag would not start Docker Publish. It also cannot write to other repositories, and cannot push commits that touch `.github/workflows`. |
| Without `RELEASE_TOKEN` | The workflows still work, degraded: the release branch is pushed with `GITHUB_TOKEN` when GitHub allows it and the run summary links "open the PR" (one extra click; a PR opened by a person runs CI); the tag is pushed and Docker Publish + Release are started by dispatch; cross-repo follow-ups are skipped with a message. |
| Variable `RELEASE_TRAIN_ANCHOR` (optional) | The first train Monday, `YYYY-MM-DD`; default `2026-10-05`. |
| A development checkout: `git config remote.origin.tagOpt --tags` | So the dev identity sees new tags. |

## 8. Decisions

### 8.1 Decisions (2026-10-02)

| # | Decision | Outcome |
|---|---|---|
| O1 | Cadence | **Release train every 2 weeks, Monday, every other week**, plus **immediate patch releases** for security and critical fixes. |
| O2 | Version numbers | **Proposed automatically** from conventional commits since the last tag (before 1.0.0: breaking → minor, feat → minor, fix/perf/others → patch); **a maintainer confirms by running the workflow**. |
| O3 | Source of truth | One `vX.Y.Z` monorepo tag for API and web (already decided for the monorepo, kept). |
| O4 | Compatibility manifest | `versions.yaml` at the repository root, consumed by compose, Helm and API defaults. |

### 8.2 Decisions taken in this RFC (open to revision)

| # | Decision | Choice | Why |
|---|---|---|---|
| O5 | Version on `/health` | **No.** `/health` stays `{status}` | The exact build helps an anonymous attacker and nobody else; signed-in users and monitoring with a session have `/api/v1/version`. |
| O6 | Dev base | **highest tag**, not the next proposal | Computable everywhere from tags alone, stable between commits, one answer for API, web and sensor. |
| O7 | First train | **v0.9.0** (proposed: one breaking change and many features since v0.8.0), on the first train Monday after the train workflows merge | It also fixes the Helm chart, whose default `appVersion` is v0.9.0. |
| O8 | Helm until v0.9.0 exists | **Do not** point charts 0.5.0+ back at v0.8.0 | They need the v0.9.0 API (sensor rename) and image names that start with v0.9.0. The chart README says to use chart 0.4.1 for v0.8.0; the chart CI warns while `appVersion` is not a published tag. |

## 9. Phases

| Phase | Scope | Where |
|---|---|---|
| **P0** | This RFC; `versions.yaml`, `sync-versions.sh`, Version consistency job, drift fixes (sensor v0.6.4, SDK v0.14.0 defaults; `package.json` 0.0.0) | openctem |
| **P1** | Release Train, Release Publish, Release Reminder workflows and their scripts with shell tests; `release.yml` dispatchable; docs | openctem |
| **P2** | Identity triple: channels `release`/`rc`/`dev`, dev version `<tag>-dev+<sha>` in API (ldflags, air, `.git` reader) and web | openctem |
| **P3** | sdk-go and sensor Release / Release Tag workflows; sensor dev version | sdk-go, sensor |
| **P4** | Chart CI check that `appVersion` is a published tag; rc tags without `latest`; make Version consistency required | helm-charts, openctem |

## 10. Risks

- **Automation with a personal token.** `RELEASE_TOKEN` can push to `main`
  through the merge queue only; branch protection still applies. Prefer a
  GitHub App when one exists; rotate the PAT on expiry (fine-grained tokens
  expire, max one year).
- **A wrong proposal.** Non-conventional subjects count as patch; a feature
  merged with a `fix:` title ships as a patch. The changelog preview in the
  reminder issue is where a maintainer catches it, and the override fixes it.
- **Imported history.** The first proposal after the monorepo import would
  count the whole web history; excluding `ui/<last tag>` handles it once.
- **Merging `main` back into `develop`.** For a train the merge is trivial
  (`main`'s tree is an earlier `develop` tree) and the script refuses if the
  result differs from `develop`. Hotfixes skip it.

## 11. Sensor product catalog (2026-10-14)

### 11.1 Problem

The platform assumed one sensor product. `SENSOR_LATEST_VERSION`,
`SENSOR_MIN_VERSION` and the SDK floor were one sensor-wide channel, so the
Tenable.sc connector and any custom sensor built on
sdk-go were judged against the scanning sensor's releases ("unsupported" at
v0.1.0 against a v0.9.0 minimum). The defaults were Go constants rewritten by
`sync-versions.sh`, so every sensor release opened a pull request that changed
Go code in `config.go` and the sensor handler.

### 11.2 Design

- **The catalog is data.** Every top-level section of `versions.yaml` other
  than `platform`, `sdk`, `ci` and `chart` is one sensor product: `product`
  (the token the sensor reports), `latest`, `min`, `image` (no tag), `install`
  (its install-snippet set) and `release_identity` (the workflow that signs
  its image). The format stays two levels so the release scripts in every
  repository keep reading and writing it with `rel_yaml_get`/`rel_yaml_set`.
  (The sensor and sdk-go release workflows bumped `sensor.latest` and
  `sdk.latest` through a pull request here; §12 removed that.)
- **Embedded, never copied into Go.** `go:embed` cannot reach outside the Go
  module (`api/`), so `sync-versions.sh` writes a byte-for-byte copy to
  `api/internal/versions/versions.yaml`; `--check` (CI) fails while they
  differ, and so does a Go test. Package `internal/versions` parses it once at
  load and panics on anything malformed: every test of every importing package
  fails, so a bad manifest cannot build a passing API. Bumping any product,
  the SDK or the CI runner changes these two YAML files only.
- **The sensor reports its product.** It already does: the heartbeat's
  `sensor.name` (sdk-go `BaseSensorConfig.ProductName`, else the product set
  with `useragent.SetProduct`) or the User-Agent product token
  (`openctemio-sensor/0.22.2`). No contract change is needed in sdk-go or ctis.
  A sensor that reports none is the scanning sensor, which was the only
  product before products were reported.
- **Verdicts per product.** A sensor of a listed product is compared with that
  product's `latest` and `min` (update available, unsupported). A product the
  catalog does not list (a custom sensor) gets
  `version_status: unknown`: no outdated or unsupported verdict. Whether such a
  sensor works with this platform is the protocol check (a v1 sensor is
  refused) and the capabilities and tools it advertises, which dispatch already
  matches.
- **SDK.** `sdk.latest` is informational ("outdated", no health effect). The
  SDK floor is gone; `sdk.advisories` lists SDK releases with a published
  security advisory, and a sensor built with one is degraded with the warning
  `sdk_advisory`.
- **Install snippets per product.** `GET /sensors/{id}/config-templates`
  takes `?product=<id>` (a catalog id; anything else is 400), defaulting to
  the product the sensor reports when it is listed, else the scanning sensor.
  The snippets pin the product's `latest` image; `SENSOR_IMAGE` still replaces
  the scanning sensor's repository for a mirror. `GET /sensors/stats` returns
  the catalog (`products`) for the Add sensor dialog, which offers the listed
  products and, for a custom one, a link to the tool-author documentation.
- **Settings.** `SENSOR_LATEST_VERSION`, `SENSOR_MIN_VERSION`,
  `SENSOR_SDK_LATEST_VERSION` and `SENSOR_SDK_MIN_VERSION` are removed: the
  API refuses to start while one is set and says why. A per-product override
  would bring back a second source of truth for little use; a newer release
  reaches the platform through the YAML-only bump. `CI_RUNNER_*` keep their
  overrides, with defaults from the embedded manifest.

### 11.3 Threat model

- The product token, version and SDK version are the sensor's own claims,
  reduced to safe tokens before they are stored. They choose which release
  line a sensor is compared with and so only change display and health
  reasons, never what the sensor may do: authorization, grants, scope and
  dispatch do not read them. A sensor that claims another product can hide an
  "unsupported" verdict, which it could already do by claiming a newer version.
- The product query parameter is matched against the catalog (bounded token
  shape first), so nothing a caller sends reaches a shell snippet; catalog
  images and identities are validated when the manifest is parsed (image
  repository without tag, `https://github.com/openctemio/...` workflow).
- The catalog is the same for every tenant; the stats and templates responses
  carry no tenant data beyond what they did, and stay behind the existing
  `sensors:read` gates.

### 11.4 Later (documented, not built)

- **Updatable catalog feed.** New releases of the listed products now reach
  a running platform through the release feed (§12). A new *product* (its
  image, install snippets and signing identity) still comes with a platform
  release or the operator's `SENSOR_PRODUCTS_FILE`.
- **Tenant-registered custom products.** Built in §13.

## 12. Sensor and SDK releases without a platform release (2026-10-18)

### 12.1 Problem

`versions.yaml` held the newest release of other repositories
(`sensor.latest`, `sdk.latest`). Every sensor or SDK release had to open a
pull request here (the sensor and sdk-go release workflows did it, only with
`RELEASE_TOKEN`, and skipped it with a warning otherwise), and a running
instance saw the release only after the next platform release. In practice
the platform kept showing an old sensor and SDK as "latest", and its install
snippets pinned the old sensor.

### 12.2 Design

Compatibility and availability are separate:

- **Compatibility** stays in `versions.yaml`, owned by this repository: each
  product's `min`, `sdk.advisories`, and the protocols the API serves. It
  changes only when the platform's contract changes.
- **Availability** (the newest release, which drives "update available",
  the SDK's "outdated" and the version the install snippets pin) is learned at
  runtime:
  - The release feed (RFC-105) gains `components`: for each first-party
    component, the `versions.yaml` section (`sensor`, `connector-tenable`,
    `sdk`), its newest stable `vX.Y.Z`, the publication time, the notes link
    and, for a component with an image, the image manifest digest.
  - `.github/workflows/release-feed.yml` builds it every 6 hours (and after
    each platform release): `release-feed components` lists the components
    from the embedded manifest (the repository from each product's
    `release_identity`, plus sdk-go), and
    `.github/scripts/release/feed-components.sh` picks each one's newest
    release that is neither a draft nor a pre-release and whose image tag is
    published, reading its digest from the registry. A component that cannot
    be resolved fails the run, so a published feed never drops one. The
    sensor and sdk-go repositories do nothing and need no secret.
  - The instance verifies the feed as before (pinned key, rollback, expiry),
    stores it in `version_check_state`, and hands its components to
    `internal/versions` at start-up, after each online check or import, and on
    every hourly controller tick on every replica. The effective latest
    release of a built-in product or the SDK is the learned one when it is
    newer than or equal to the built-in one, else the built-in one; the
    learned digest is used only with the learned version. An operator's
    product (`SENSOR_PRODUCTS_FILE`) is never changed by the feed.
  - Handlers resolve the catalog on every request, so the Sensors page, the
    health verdicts and the install snippets follow without a restart. The
    snippets pin `image:tag@sha256:...` when the feed gave a digest and the
    image is the published one; a mirror (`SENSOR_IMAGE`) is pinned by tag.
- `latest` in `versions.yaml` now means the release this platform release was
  built with: the fallback and the floor. Moving it forward at a platform
  release is optional hygiene; a sensor or SDK release never needs it.
  `api/deploy/docker-compose.sensor.yml` (the bundled sensor) follows it
  through `sync-versions.sh`.
- The console says where the latest version comes from
  (`latest_source`: `feed`, `built_in`, `operator`): a sensor on the built-in
  latest reads "the newest release this platform knows" instead of "the
  latest release". System > Software updates lists the component releases.

### 12.3 Offline and air-gapped instances

Without the feed (no pinned key, `VERSION_CHECK_ENABLED=false`, no outbound
access) the built-in versions apply, marked as such. The override is the
existing import of the signed feed file in the console (System > Software
updates > Import): one file updates the platform and component releases
together. No per-product setting is added: §11.2 removed those because a
second source of truth drifted.

### 12.4 Threat model

| Threat | Control |
|---|---|
| A forged feed points the install snippets at another image | Ed25519 signature by a key pinned in the binary; the image repository always comes from the built-in catalog, the feed carries only a version and a digest |
| A replayed or stale feed pushes sensors back to an older release | sequence rollback check, and the effective latest is never below the built-in one |
| A re-pointed tag in the registry | the digest is inside the signed feed and the snippets pin tag and digest, so a different image fails to pull |
| A withheld feed hides new releases | bounded by the 45-day expiry; the console shows the feed as out of date |
| Cross-tenant effects | instance-level data from a signed file, no tenant input, routes and gates unchanged |

Authorization and tenant isolation are unchanged: no route, permission or
query is added; the stats and templates responses keep their `sensors:read`
gates and gain only the `latest_source` field.

### 12.5 Maintainer setup

The runtime path is inert until a release feed key is pinned
(`releasefeed.PinnedKeys`) and the `RELEASE_FEED_SIGNING_KEY` secret exists
([version check](../architecture/version-check.md#setup-maintainers)).
`RELEASE_TOKEN` is not needed for any of this.

## 13. Product-agnostic compatibility and organizations' own products (2026-10-18)

### 13.1 Problem

Organizations will build their own sensors on sdk-go. A release of such a
sensor must not need a platform change, and the platform cannot list every
product. Until now a product the catalog did not list got no verdict except
SDK advisories, and there was no way to say "this SDK is too old for this
platform" (§11.2 removed the SDK floor).

### 13.2 Design

- **Compatibility from declarations.** The platform judges any sensor by what
  it declares (protocol, SDK name and version, capabilities, tools) against
  ranges it owns: the protocols it serves, `sdk.min` and `sdk.advisories`.
  `sdk.min` is new in `versions.yaml` (empty today): a heartbeating sensor
  built with an older sdk-go is degraded with the critical reason
  `sdk_unsupported`, whatever its product. It is raised only when a protocol
  change requires it. SDK checks apply only to sensors built with sdk-go (SDK
  name `openctem-sdk-go`, or none); a sensor on another SDK is `unknown`.
- **Freshness of an organization's product is the organization's data.**
  Table `tenant_sensor_products` (migration `002908`): per organization and
  product token, an optional latest and minimum release. Routes
  `GET /api/v1/sensors/custom-products` (`sensors:read`) and
  `PUT|DELETE /api/v1/sensors/custom-products/{product}` (`sensors:write`),
  audited, at most 50 per organization. The sensor handler adds the
  organization's lines to its health policy for products the catalog does not
  list (a catalog line is never replaced), so its sensors get `latest`,
  `update_available` and `unsupported` verdicts.
- **No line, no freshness verdict.** A custom product without a recorded line
  gets only the SDK and protocol verdicts (`version_status: unknown`).
- **Rejected: an organization-published signed feed URL.** It would add an
  outbound request per organization (SSRF surface, egress allow-lists, key
  handling per organization, failure states) to save typing one version.
  Revisit when organizations ask for it repeatedly.
- The contract for sensor authors:
  [sensor compatibility](../architecture/sensor-compatibility.md).

### 13.3 Threat model

| Threat | Control |
|---|---|
| A sensor declares hostile values | sanitized at ingest to bounded tokens and `vX.Y.Z` (existing); they select a release line and SDK verdict only, never authorization, grants, scope or dispatch |
| An organization records a line for a first-party product (to hide "unsupported", or to confuse its users) | names starting with `openctemio-` are refused in the domain and by a database CHECK; products the platform catalog lists are refused by the service |
| A sensor claims a first-party product name | the claim selects the line shown to its own organization only, as before (§11.3); proving first-party origin would need image attestation, out of scope |
| Cross-organization read or write | the tenant comes from the token; every query carries `tenant_id`; a route test shows another organization's sensor of the same product name gets no verdict, its list is empty and its delete answers 404 |
| Oversized or hostile input | token and version shapes in the domain and in CHECKs, 4 KiB body with unknown fields refused, 50 rows per organization |
| Members change fleet settings | writes need `sensors:write` (owners and administrators); reads `sensors:read` |
