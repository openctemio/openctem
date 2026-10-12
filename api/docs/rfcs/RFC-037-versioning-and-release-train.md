# RFC-037 — Versioning rule and release train

> Status: **Accepted** (decisions 2026-10-02, §8; design PR #787). P0–P2 are
> implemented in this repository (`versions.yaml`, the Release Train, Release
> Publish and Release Reminder workflows, the version/commit/channel triple in
> `pkg/version`); P3 and P4 belong to the sdk-go, sensor and helm-charts
> repositories (§9).
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
- `web/package.json` is `"version": "0.0.0"` permanently. npm requires the
  field to be valid SemVer; the web app's version comes from the build.
- Release builds get the version from the tag (`--build-arg VERSION`,
  ldflags, `NEXT_PUBLIC_APP_VERSION`), never from a file in the tree.

### 3.5 The compatibility manifest

```yaml
# versions.yaml (repository root)
platform:
  release: v0.8.0   # newest released tag; bumped by the release workflow after tagging
sensor:
  latest: v0.6.4    # install snippets pin it; older sensors show "update available"
  min: ""           # older sensors are degraded "version unsupported"; "" = none
sdk:
  latest: v0.14.0   # sensors built with an older SDK are "outdated"
  min: ""           # older is degraded "SDK below minimum"; "" = none
chart:
  version: 0.4.1    # newest published chart whose appVersion is platform.release
```

`.github/scripts/release/sync-versions.sh` copies it into its consumers:
`config.Default*` in `api/internal/config`, the install-snippet image in the
sensor handler, the `SENSOR_*` defaults in `api/deploy/docker-compose.yml`,
`OPENCTEM_VERSION` in `api/deploy/.env.example`, and the examples in
`api/.env.example`. The consumer table in the script is the only place a
versioned default may live. With `--check` it is the **Version consistency**
CI job, which also fails when `web/package.json` is not `0.0.0` or when
`platform.release` names a tag that does not exist.

Who bumps what:

| Field | Bumped by |
|---|---|
| `platform.release` | the platform release workflow, in the post-release PR to `develop` |
| `sensor.latest` | the sensor release workflow, in a PR to `openctem` after it tags (until that exists: by hand) |
| `sdk.latest` | the sdk-go release workflow, same way |
| `*.min` | a person, deliberately: raising a minimum degrades fleets |
| `chart.version` | the platform release workflow, together with the helm-charts PR it opens |

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
                   cut    release/vX.Y.Z = that SHA + `merge -s ours origin/main`
                          (tree == develop's, main recorded as a parent)
                          PR release/vX.Y.Z → main, queued for merge (MERGE)
Merge queue        required checks on the merge group → merge into main
Release Publish    (on that PR's merge) verify main's tree == the release branch's,
                   annotated tag vX.Y.Z on the merge commit
                   → Docker Publish + Release (images, GitHub Release, notes
                     with @mentions escaped and emails dropped)
                   follow-ups:
                   - PR to develop: merge main back (tags become reachable),
                     versions.yaml platform.release = vX.Y.Z (+ sync)
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
   commits (`-x`), and continues as in §4.2. The post-release PR to `develop`
   only bumps `versions.yaml`; it does not merge `main` back (the fix is
   already on `develop`).

### 4.4 Gates

- Every required check (`API CI OK`, `Web CI OK`, `CodeQL OK`,
  `All-in-one OK`, `Secret Scanning`, `Workflow Lint`) is `success` on the
  chosen `develop` commit; a cancelled or missing check counts as red.
- The version is a `vX.Y.Z` greater than the last tag, and the tag and the
  release branch do not exist yet.
- The release branch's tree equals the chosen commit's tree (train), and
  `main`'s tree after the merge equals the release branch's; otherwise no tag
  is pushed.
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
  (needs `RELEASE_TOKEN`).
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
