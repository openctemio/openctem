# CI/CD

CI for the `openctemio/openctem` monorepo (`api/` + `web/`). All workflows live
in the repository root's [`.github/workflows/`](../../../.github/workflows/);
`api/` and `web/` have none of their own. The workflow files are the source of
truth: this page describes them as of the monorepo cutover (2026-10-02).

## Workflows

| Workflow (file) | Triggers | What it does | Gate check |
|-----------------|----------|--------------|------------|
| API CI (`api-ci.yml`) | PR / push to `main`, `develop`; merge queue | Migration safety, SQL schema drift, security gates, OpenAPI contract, gateway routing, lint, tests, protocol-v1 compat, build, Docker build | **API CI OK** |
| Web CI (`web-ci.yml`) | PR / push to `main`, `develop`; merge queue | Generated API types check, type-check, ESLint, Prettier, palette drift, Vitest, `next build` (push only) | **Web CI OK** |
| CodeQL (`codeql.yml`) | PR / push; merge queue; weekly (Mon 00:00 UTC) | CodeQL for Go (built inside `api/`) and JavaScript/TypeScript (`web/`), one category per language | **CodeQL OK** |
| All-in-one CI (`allinone-ci.yml`) | PR / push; merge queue | Builds `openctem-api`, `openctem-web` and the all-in-one `openctem` image exactly as a release does, smoke-tests them (arch, ELF, executes) and runs the all-in-one in both gateway modes against Postgres + Redis. Nothing is pushed. | **All-in-one OK** |
| Repository Security (`repo-security.yml`) | PR / push; merge queue; weekly | Betterleaks over the full git history (root `.betterleaks.toml`, `.gitleaksignore`); actionlint over the workflows | **Secret Scanning**, **Workflow Lint** |
| API Security (`api-security.yml`) | PR / push; merge queue; weekly | govulncheck, Trivy (fs), Semgrep, Snyk (only if `vars.ENABLE_SNYK == 'true'`), license check, image scan (only for `main` / weekly) | — |
| Web Security (`web-security.yml`) | PR / push; merge queue; weekly | npm audit, Trivy (fs), ESLint security rules, Snyk (opt-in as above), image scan (only for `main` / weekly) | — |
| API Fuzz (`api-fuzz.yml`) | Nightly (03:17 UTC), manual | 10 minutes of `FuzzStrictCTIS` (the protocol-v2 results decoder); uploads a crasher artifact on failure | — |
| Docker Publish (`docker-publish.yml`) | Tag `v*`, manual | Builds, smoke-tests, publishes, signs and SBOMs every image (see [Images](#images)) | — |
| Release (`release.yml`) | Tag `v*` | GitHub Release with `bootstrap-admin` binaries + checksums and the image pull lines | — |

Scheduled runs (weekly security, nightly fuzz) run from the default branch, `main`.

### Required checks

Branch protection on `main` and `develop` requires exactly these six checks
(strict: the branch must be up to date with its base):

`API CI OK` · `Web CI OK` · `CodeQL OK` · `All-in-one OK` · `Secret Scanning` · `Workflow Lint`

The four `… OK` checks are aggregator jobs (`if: always()`): they pass when every
job they depend on passed **or was skipped**, and fail when any failed or was
cancelled. The other jobs are not required individually; they reach the merge
through their aggregator. API Security and Web Security are not required.

Code-scanning result checks (CodeQL, Semgrep, Trivy alerts) are separate from
these workflow gates.

### Path filtering

No workflow uses `on.<event>.paths`: a workflow skipped that way leaves its
required checks *Pending* forever. Instead every workflow always starts, and a
`changes` job runs [`.github/scripts/changed.sh`](../../../.github/scripts/changed.sh),
which diffs the PR (against its base) or the push (against `before`) and decides
whether the real jobs run. A job skipped by `if:` reports success to its aggregator.

| Workflow | Runs its jobs when the change touches |
|----------|----------------------------------------|
| API CI, API Security | `api/`, `.github/workflows/api-*`, `.github/scripts/` |
| Web CI | `web/`, **`api/api/openapi/swagger.yaml`**, `.github/workflows/web-*`, `.github/scripts/` |
| Web Security | `web/`, `.github/workflows/web-*`, `.github/scripts/` |
| CodeQL | Go leg: `api/`; JS/TS leg: `web/`; both: `.github/workflows/codeql.yml` |
| All-in-one CI | `deploy/`, `api/deploy/gateway/`, `api/Dockerfile`, `api/.dockerignore`, `api/go.mod`, `web/Dockerfile`, `web/.dockerignore`, `web/package-lock.json`, `web/server-with-ws.mjs`, `web/next.config.ts`, `.github/scripts/smoke-*`, `.github/workflows/allinone-ci.yml` |
| Repository Security | always (no filter) |

Any event that is not a PR or an ordinary branch push (schedule, manual
dispatch, tag, merge queue, first push of a branch) runs everything.

Each workflow cancels an older run for the same PR or branch; tag and scheduled
runs are never cancelled.

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
| Migration Safety | PRs only. Flags destructive migrations against the base. |
| SQL Schema Drift | `api/scripts/check-sql-schema.sh`: prepares every SQL statement against a migrations-only database. |
| Security Gates | `api/scripts/security-lint.sh` (checks out `sensor` and `sdk-go` alongside), tenant-scope analyzer, sensor vocabulary guard. |
| OpenAPI Contract | See above. |
| Gateway Routing | `api/deploy/gateway/smoke-test.sh` + renders the production compose files. |
| Lint | `go vet`, staticcheck, and golangci-lint v1.64.8 on **new** code only (PRs: `make lint-new` with `--new-from-rev` against `.github/scripts/effective-base.sh`). `make -C api lint-ci` runs the same locally. |
| Test | `go test -race` against Postgres 17 + Redis 7 service containers. |
| Protocol v1 Compatibility | Runs the pinned, last-released sdk-go against a freshly built server (`api/scripts/compat-v1.sh`). |
| Build | `cmd/server` and `cmd/bootstrap-admin` binaries. |
| Docker Build | Pushes to `main` only; builds the image, does not push it. |

All Go jobs run with `GOWORK=off` and `working-directory: api`.

## Releases

**One tag, `vX.Y.Z` on `main`, releases the whole product.** API and web always
share the version. There is no separate web release any more.

- `docker-publish.yml` and `release.yml` both trigger on `v*`.
- `ui/vX.Y.Z` tags are the old `openctemio/ui` tags, imported with its history.
  They release nothing: the `v*` glob does not match across `/`. Never create one.
- `vX.Y.Z-staging` (or a manual dispatch with `environment: staging`) publishes
  `vX.Y.Z-staging` + `staging-latest` instead of `vX.Y.Z` + `latest`.
- Releases v0.1.x–v0.8.0 on this repository's Releases page are the API releases
  from before the merge; the old web releases stay on the archived `openctemio/ui`.

```bash
# production release (from main)
git tag v0.9.0 && git push origin v0.9.0

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
2. All six required checks green, branch up to date.
3. Merge with a merge commit or squash, never "rebase and merge" for branches
   that contain merges.
4. Release: `develop` → PR to `main` → tag `vX.Y.Z` on `main`.

Dependabot ([`.github/dependabot.yml`](../../../.github/dependabot.yml)) opens PRs
against `develop`: gomod for `/api` (and monthly for the compat harness), npm for
`/web`, and one github-actions entry for the root workflows.

## Secrets and settings

| Name | Kind | Used by |
|------|------|---------|
| `GITHUB_TOKEN` | built-in | GHCR push, release, SARIF upload |
| `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | secret (optional) | authenticated base-image pulls; Docker Hub mirror when set |
| `SNYK_TOKEN` + `vars.ENABLE_SNYK` | secret + variable (optional) | Snyk jobs in API / Web Security |

The legacy `ui` GHCR package was created by `openctemio/ui`; this repository needs
**Write** in that package's "Manage Actions access" for the legacy copy to succeed.

## Troubleshooting

- **A required check stays Pending.** Something added `on.paths` to a workflow;
  remove it and gate the jobs through the `changes` job instead.
- **Web CI fails on `check:api-types`.** The spec changed without regenerating the
  web types: `make api-types`, commit `web/src/lib/api/generated/api.types.ts`.
- **golangci-lint reports issues you didn't touch.** The PR's base is stale; rebase
  on `develop` (lint diffs against `.github/scripts/effective-base.sh`).
- **govulncheck fails on every PR at once.** A new Go stdlib CVE: bump the Go
  version everywhere it is pinned, together: `GO_VERSION` in `api-ci.yml`,
  `api-security.yml` and `release.yml`, and `go-version` in `codeql.yml` and
  `api-fuzz.yml`.
- **Image not found after a tag.** Check the Docker Publish run; the tag must match
  `v<major>.<minor>.<patch>[-suffix]`. Images for v0.8.0 and earlier exist only
  under the legacy `api` / `ui` names.
