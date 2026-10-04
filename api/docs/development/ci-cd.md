# CI/CD

CI for the `openctemio/openctem` monorepo (`api/` + `web/`). All workflows live
in the repository root's [`.github/workflows/`](../../../.github/workflows/);
`api/` and `web/` have none of their own. The workflow files are the source of
truth: this page describes them as of the merge-queue routing (#730, 2026-10-02).

## Workflows

| Workflow (file) | Triggers | What it does | Gate check |
|-----------------|----------|--------------|------------|
| API CI (`api-ci.yml`) | PR / push to `main`, `develop`; merge queue | `API static checks` (one job: migration safety, SQL schema drift, security gates, OpenAPI contract, gateway routing, lint), tests, protocol-v1 compat + release binaries, Docker build; see [Tiers](#tiers) | **API CI OK** |
| Web CI (`web-ci.yml`) | PR / push to `main`, `develop`; merge queue | `Web checks` (one job: generated API types check, type-check, ESLint, Prettier, palette drift, Vitest); `next build` (push only) | **Web CI OK** |
| CodeQL (`codeql.yml`) | PR / push; merge queue; weekly (Mon 00:00 UTC) | One matrix over the languages: Go (built inside `api/`) and JavaScript/TypeScript (`web/`), one category per language. PR and merge queue: only the changed language(s). Push to `develop`/`main` and weekly: both, so each branch keeps a fresh baseline per category | **CodeQL OK** |
| All-in-one CI (`allinone-ci.yml`) | PR / push; merge queue | Builds `openctem-api`, `openctem-web` and the all-in-one `openctem` image exactly as a release does, smoke-tests them (arch, ELF, executes) and runs the all-in-one in both gateway modes against Postgres + Redis. Nothing is pushed. Merge queue and pushes only (see [Tiers](#tiers)). | **All-in-one OK** |
| Repository Security (`repo-security.yml`) | PR / push; merge queue; weekly | Betterleaks (root `.betterleaks.toml`, `.gitleaksignore`): a PR or queued group scans only its own commits (`base..head`); a push to `develop`/`main` and the weekly run scan the full history. actionlint over the workflows | **Secret Scanning**, **Workflow Lint** |
| API Security (`api-security.yml`) | PR / push (`paths:` api side, see below); weekly | One job for govulncheck + Trivy (fs) + license check; Semgrep; Snyk (only if `vars.ENABLE_SNYK == 'true'`), license check, image scan (only for `main` / weekly) | — |
| Web Security (`web-security.yml`) | PR / push (`paths:` web side, see below); weekly | One job for npm audit + Trivy (fs) + ESLint security rules; Snyk (opt-in as above), image scan (only for `main` / weekly) | — |
| API Fuzz (`api-fuzz.yml`) | Nightly (03:17 UTC), manual | 10 minutes of `FuzzStrictCTIS` (the protocol-v2 results decoder); uploads a crasher artifact on failure | — |
| Docker Publish (`docker-publish.yml`) | Tag `v*`, manual | Builds, smoke-tests, publishes, signs and SBOMs every image (see [Images](#images)) | — |
| Release (`release.yml`) | Tag `v*`; dispatch on a tag | GitHub Release with `bootstrap-admin` binaries + checksums and the image pull lines | — |
| Release Train (`release-train.yml`) | Manual (the owner presses Run) | Proposes the version from conventional commits, picks the newest develop commit with every required check green, builds `release/vX.Y.Z`, opens and queues the release PR (see [Releases](#releases)) | — |
| Release Publish (`release-publish.yml`) | A `release/v*` PR merged into `main`; manual | Tags `vX.Y.Z`, starts Docker Publish + Release, opens the develop and helm-charts follow-up PRs, closes the train issue | — |
| Release Reminder (`release-reminder.yml`) | Mondays 01:00 UTC (train weeks only); manual | Opens/updates the issue "Release train vX.Y.Z" with the proposal and changelog preview | — |
| Release Tooling (`release-tooling.yml`) | PR / push touching `versions.yaml`, the release scripts or a versioned default | **Release scripts** (shellcheck + shell tests) and **Version consistency** (`sync-versions.sh --check`) | — |

Scheduled runs (weekly security, nightly fuzz) run from the default branch, `main`.

### Required checks

Branch protection on `main` and `develop` requires exactly these six checks.
Merges go through the GitHub merge queue (see [Merge queue](#merge-queue)); the
strict "branch must be up to date" rule is off, because the queue itself tests
each PR on top of the current base:

`API CI OK` · `Web CI OK` · `CodeQL OK` · `All-in-one OK` · `Secret Scanning` · `Workflow Lint`

The four `… OK` checks are aggregator jobs (`if: always()`): they pass when every
job they depend on passed **or was skipped**, and fail when any failed or was
cancelled. The other jobs are not required individually; they reach the merge
through their aggregator. API Security and Web Security are not required.

Code-scanning result checks (CodeQL, Semgrep, Trivy alerts) are separate from
these workflow gates.

### Path filtering

One rule set, in [`.github/scripts/changed.sh`](../../../.github/scripts/changed.sh),
decides two outputs, `api` and `web`, for every workflow:

| Changed path | api | web |
|--------------|-----|-----|
| `api/**` | ✓ | |
| `web/**` | | ✓ |
| `api/api/openapi/swagger.yaml` (the web types are generated from it) | ✓ | ✓ |
| Shared: root `Makefile`, `go.work*`, `.github/**`, `deploy/**` | ✓ | ✓ |
| Anything else (root docs, `.githooks/`) | | |

The diff range depends on the event:

| Event | Range |
|-------|-------|
| `pull_request` | the PR against its base (`origin/<base>...HEAD`) |
| `push` | `before..HEAD` |
| `merge_group` | `merge_group.base_sha..head_sha`, exactly the queued PR |
| schedule, manual dispatch, tag, a branch's first push, missing SHAs | everything runs |

How each workflow uses the outputs:

| Workflow | Scoping |
|----------|---------|
| API CI | always starts; real jobs run when `api` (which ones: [Tiers](#tiers)) |
| Web CI | always starts; real jobs run when `web` |
| CodeQL | Go when `api`, JS/TS when `web` (PR); nothing in the merge queue; both on push and weekly |
| All-in-one CI | always starts; builds when `api` or `web` (both images are built from the whole component directory), in the merge queue and on pushes only |
| Repository Security | always runs (secret scan diff-scoped on PR and merge queue) |
| API Security | `on.paths`: `api/**` + shared files. Does not start at all for a web-only change |
| Web Security | `on.paths`: `web/**` + shared files. Does not start at all for an API-only change |

Workflows that carry a required check never use `on.<event>.paths`: a workflow
skipped that way leaves its required checks *Pending* forever. They always start,
and a job skipped by `if:` reports success to its aggregator. API Security and
Web Security carry no required check, so they can use `on.paths`. If you change
the shared list, change it in `changed.sh` and in both of those `paths:` lists.

Each workflow cancels an older run for the same PR or branch; tag and scheduled
runs are never cancelled.

### Merge queue

1. A PR runs CI as usual (`pull_request`). When it is green and approved,
   **Merge when ready** adds it to the queue.
2. The queue creates `gh-readonly-queue/<base>/pr-<n>-<sha>`: the base (or the
   group ahead of it in the queue) plus this PR, and fires `merge_group`
   (`checks_requested`).
3. API CI, Web CI, All-in-one CI and Repository Security run the full tier (see
   [Tiers](#tiers)) on that ref; CodeQL only reports `CodeQL OK`. `changed.sh`
   diffs `base_sha..head_sha`, so a queued web-only PR runs only web jobs, as it
   did on the PR.
4. All six required checks report on every queue ref: the four `… OK`
   aggregators run with `if: always()` and pass when their jobs were skipped;
   Secret Scanning and Workflow Lint are unconditional jobs. Nothing stays Pending.
5. When all six pass, the queue fast-forwards the base branch, and the `push` run
   (path-scoped, plus CodeQL on both languages) refreshes the branch's baseline.
6. A failure removes the PR from the queue; the groups behind it are rebuilt.

### Tiers

Every PR is tested twice (on the PR, then in the queue) on the free plan's ~20
concurrent hosted runners, so the work is split. Self-hosted runners are not
used: this is a public repository, and a fork PR would run code on the host.

| Tier | Events | API CI | Web CI | All-in-one CI | CodeQL |
|------|--------|--------|--------|---------------|--------|
| Fast | `pull_request` | `API static checks` + `Unit tests` (`go test -race`, no database: DB-backed tests skip themselves without `DATABASE_URL`) + `Tests (least-privilege DB role)` | `Web checks` | build skipped | changed language(s) |
| Full | `merge_group`, push to `develop`/`main` | `API static checks` + `Tests (Postgres + Redis)` + `Tests (least-privilege DB role)` + `Protocol v1 Compatibility` (+ release binaries); Docker build on `main` | `Web checks`; `next build` on push | images built and smoke-tested | queue: none (the PR head was analysed); push: both |

The `… OK` aggregators pass when a job was skipped because its area did not
change, but when the area did change they also require that **this event's
tier ran and passed**. In the queue, `API CI OK` fails unless the integration
tests and the compat run succeeded, and `All-in-one OK` fails unless the image
build succeeded. Nothing reaches `develop`/`main` on the fast tier alone.

Concurrency: a newer push to a PR cancels that PR's older run
(`cancel-in-progress` only for `pull_request`). Merge-queue runs are never
cancelled, because a cancelled required check ejects the group. Branch pushes,
tags and schedules are never cancelled either.

PR-only steps (Migration Safety, golangci-lint on new code) are skipped in the
queue: they already ran on the PR. API Security and Web Security do not run in
the queue (no required check; the PR and the push scan the change).

### Toolchain versions

- **Go:** every `actions/setup-go` step uses `go-version-file: api/go.mod`, which
  reads the `toolchain` directive (currently `go1.26.8`). setup-go sets
  `GOTOOLCHAIN=local`, so this is exactly the Go that tests, CodeQL, govulncheck
  and the release binaries use. `api/Dockerfile` and `api/Dockerfile.admin-cli`
  pin their `golang:` base image separately: bump them with `go.mod`.
- **Node:** every `actions/setup-node` step uses `node-version-file: web/.nvmrc`
  (`26`), the same major as `web/Dockerfile` (`node:26-alpine`). Node 25+ ships
  its own `localStorage`; `web/src/test/setup.ts` points Vitest back at jsdom's.

### The API ↔ web contract

`api/api/openapi/swagger.yaml` is generated from the Go handler annotations.
API CI's **OpenAPI Contract** job (`api/scripts/check-openapi.sh`) fails if the
spec does not match the handlers. Web CI's first quality step,
`npm run check:api-types`, fails if `web/src/lib/api/generated/api.types.ts` is
not what the spec generates; that is why a spec change also triggers Web CI.
Locally:

```bash
make -C api swagger   # regenerate the spec
make api-types        # regenerate the web wire types
make check            # both contract checks, as CI runs them
```

### What the API jobs check

| Job | Notes |
|-----|-------|
| *All of the rows down to Lint are steps of one job, `API static checks`.* | |
| Migration Safety | PRs only. Flags destructive migrations against the base. |
| Migration Versions | `.github/scripts/check-migration-versions.sh` (tests: `check-migration-versions.test.sh`). Fails if two migrations share a version, and, on a PR or in the merge queue, if a migration the change adds is not above the base's highest version (golang-migrate silently skips lower versions on databases already past them). In the queue the base is `merge_group.base_sha`, so two queued PRs that picked the same number cannot both land: the second is told to renumber to max+1. |
| SQL Schema Drift | `api/scripts/check-sql-schema.sh`: prepares every SQL statement against a migrations-only database. |
| Security Gates | `api/scripts/security-lint.sh` (checks out `sensor` and `sdk-go` alongside), tenant-scope analyzer, sensor vocabulary guard. |
| OpenAPI Contract | See above. |
| Gateway Routing | `api/deploy/gateway/smoke-test.sh` + renders the production compose files. |
| Lint | `go vet`, staticcheck, and golangci-lint v1.64.8 on **new** code only (PRs: `make lint-new` with `--new-from-rev` against `.github/scripts/effective-base.sh`). `make -C api lint-ci` runs the same locally. |
| Unit tests | PRs. `go test -race -timeout 20m ./...` with no database (DB-backed tests skip). |
| Tests (Postgres + Redis) | Merge queue and pushes. The same suite against Postgres 17 + Redis 7 service containers. |
| Tests (least-privilege DB role) | Both tiers. Bootstraps a fresh database with `api/deploy/postgres/least-privilege-roles.sql`, applies every migration as `openctem_migrator`, then runs the DB-backed suite as `openctem_app` (DML only). It fails if a migration needs a superuser or the API needs more than DML. See `api/docs/deployment/database-roles.md`. |
| Protocol v1 Compatibility | Merge queue and pushes. Runs the pinned, last-released sdk-go against a freshly built server (`api/scripts/compat-v1.sh`), then builds and uploads static linux/amd64 `cmd/server` and `cmd/bootstrap-admin` binaries. |
| Docker Build | Pushes to `main` only; builds the image, does not push it. |

All Go jobs run with `GOWORK=off` and `working-directory: api`.

## Releases

**One tag, `vX.Y.Z` on `main`, releases the whole product.** API and web always
share the version. There is no separate web release any more. The rule, the
cadence and the tooling are [RFC-037](../rfcs/RFC-037-versioning-and-release-train.md);
how to run a release is [Versioning and releases](../architecture/versioning-and-releases.md).

- **Release train every other Monday**, plus immediate patch releases for
  security and critical fixes. Run **Release Train** (Actions); do not tag by
  hand.
- `docker-publish.yml` and `release.yml` both trigger on `v*`.
- `ui/vX.Y.Z` tags are the old `openctemio/ui` tags, imported with its history.
  They release nothing: the `v*` glob does not match across `/`. Never create one.
- `vX.Y.Z-staging` (or a manual dispatch with `environment: staging`) publishes
  `vX.Y.Z-staging` + `staging-latest` instead of `vX.Y.Z` + `latest`.
- Releases v0.1.x–v0.8.0 on this repository's Releases page are the API releases
  from before the merge; the old web releases stay on the archived `openctemio/ui`.

```bash
# a release: Actions > Release Train > Run (dry_run first), or
gh workflow run release-train.yml --ref develop -f dry_run=false

# manual publish of an existing version (e.g. a staging build)
gh workflow run docker-publish.yml -f version=v0.9.0 -f environment=staging
```

### Images

All images go to GHCR, are multi-arch (linux/amd64 + linux/arm64), are built on a
**native** runner per architecture and smoke-tested there (config arch, ELF
`e_machine`, the binary executes) before anything is pushed, then merged into one
manifest list per tag, signed with cosign (keyless) and given an SPDX SBOM that
is attached to the GitHub Release.

| Image | Built from | Contents |
|-------|-----------|----------|
| `ghcr.io/openctemio/openctem-api` | `api/Dockerfile` (`production` target) | API server, port 8080 |
| `ghcr.io/openctemio/openctem-web` | `web/Dockerfile` | Next.js console, port 3000 |
| `ghcr.io/openctemio/openctem` | `deploy/allinone/` FROM the two above + `api/deploy/gateway` | All-in-one: API + web + Caddy gateway. `GATEWAY=on` (default) serves only 443; `GATEWAY=off` serves 8080 + 3000. Postgres/Redis external. |
| `ghcr.io/openctemio/migrations` | `api/Dockerfile.migrations` | One-shot migration runner |
| `ghcr.io/openctemio/seed` | `api/Dockerfile.seed` | Seeding utility |
| `ghcr.io/openctemio/admin-cli` | `api/Dockerfile.admin-cli` | Admin CLI |

**Legacy names.** During a transition window (two releases, per the root
README) `ghcr.io/openctemio/api` and `ghcr.io/openctemio/ui` receive the same
manifests as `openctem-api` and `openctem-web` (`crane copy`), so existing
compose files, Helm values and `docker pull` lines keep working. The window
ends when the `legacy` field of the matrix entry in `docker-publish.yml` is blanked.
The legacy names are also the only ones that hold v0.8.0 and earlier.

**Docker Hub** mirroring (`mirror-to-dockerhub`) runs only when the
`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets are set. They currently are not,
so bare `openctemio/<name>` references (Docker Hub) do not resolve: always use
the `ghcr.io/openctemio/…` names.

Verify a signature:

```bash
cosign verify ghcr.io/openctemio/openctem:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Release binaries

`release.yml` builds `bootstrap-admin` for linux/amd64, linux/arm64,
darwin/amd64, darwin/arm64 and windows/amd64, published as
`bootstrap-admin-<version>-<os>-<arch>.tar.gz` (`.zip` on Windows) with
`checksums-sha256.txt`. The release notes are generated, plus the image pull lines.

## Local equivalents

From the repository root (see the root [`Makefile`](../../../Makefile), `make help`):

```bash
make setup       # go mod download (api), npm ci (web), make hooks
make hooks       # git config core.hooksPath .githooks
make lint        # make -C api lint-ci; web lint + type-check
make test        # go test (api), vitest (web)
make build       # go build (api), next build (web)
make check       # OpenAPI contract + generated web types
make allinone    # build openctem-api:local, openctem-web:local, openctem:local
make api-<t>     # any api/Makefile target, e.g. make api-swagger
make web-<s>     # any web npm script, e.g. make web-format
```

The git hooks in [`.githooks/`](../../../.githooks/) run on commit: `pre-commit`
type-checks and lint-stages `web/` when web files are staged and runs `gofmt` on
staged Go files; `commit-msg` rejects AI attribution lines.

## Branch strategy

```
main     release branch; v* tags are cut here
develop  integration branch; every PR targets develop
  feature/…, fix/…, docs/…, chore/…
```

1. Branch from `develop`, open the PR against `develop`. One PR may change both
   `api/` and `web/`.
2. All six required checks green, then **Merge when ready** (merge queue).
3. Merge with a merge commit or squash, never "rebase and merge" for branches
   that contain merges.
4. Release: **Release Train** builds `release/vX.Y.Z` from a green `develop`
   commit and opens the PR to `main`; **Release Publish** tags `vX.Y.Z` on the
   merge commit (RFC-037).

Dependabot ([`.github/dependabot.yml`](../../../.github/dependabot.yml)) opens PRs
against `develop`: gomod for `/api` (and monthly for the compat harness), npm for
`/web`, and one github-actions entry for the root workflows.

## Secrets and settings

| Name | Kind | Used by |
|------|------|---------|
| `GITHUB_TOKEN` | built-in | GHCR push, release, SARIF upload |
| `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | secret (optional) | authenticated base-image pulls; Docker Hub mirror when set |
| `SNYK_TOKEN` + `vars.ENABLE_SNYK` | secret + variable (optional) | Snyk jobs in API / Web Security |
| `RELEASE_TOKEN` | secret (recommended) | Release Train / Publish: pushes and PRs that start CI, the tag push that starts Docker Publish, the helm-charts PR. Fine-grained PAT or App token for `openctem`, `helm-charts`, `sdk-go`, `sensor`: Contents, Pull requests and Workflows read/write. Without it the release still works, with one extra click per PR and no helm-charts PR |
| `vars.RELEASE_TRAIN_ANCHOR` | variable (optional) | The first train Monday (`YYYY-MM-DD`, default `2026-10-05`) |

The legacy `ui` GHCR package was created by `openctemio/ui`; this repository needs
**Write** in that package's "Manage Actions access" for the legacy copy to succeed.

## Troubleshooting

- **A required check stays Pending.** Something added `on.paths` to a workflow
  that carries a required check, or dropped its `merge_group` trigger; gate the
  jobs through the `changes` job instead.
- **Web CI fails on `check:api-types`.** The spec changed without regenerating the
  web types: `make api-types`, commit `web/src/lib/api/generated/api.types.ts`.
- **golangci-lint reports issues you didn't touch.** The PR's base is stale; rebase
  on `develop` (lint diffs against `.github/scripts/effective-base.sh`).
- **govulncheck fails on every PR at once.** A new Go stdlib CVE: bump the
  `toolchain` directive in `api/go.mod` (CI follows it) and the `golang:` base
  image in `api/Dockerfile` and `api/Dockerfile.admin-cli`.
- **Image not found after a tag.** Check the Docker Publish run; the tag must match
  `v<major>.<minor>.<patch>[-suffix]`. Images for v0.8.0 and earlier exist only
  under the legacy `api` / `ui` names.
