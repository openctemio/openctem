# CI/CD

CI for the `openctemio/openctem` monorepo (`api/` + `web/`). All workflows live
in the repository root's [`.github/workflows/`](../../../.github/workflows/);
`api/` and `web/` have none of their own. The workflow files are the source of
truth: this page describes them as of the merge-queue routing (#730, 2026-10-02).

## Workflows

| Workflow (file) | Triggers | What it does | Gate check |
|-----------------|----------|--------------|------------|
| API CI (`api-ci.yml`) | PR / push to `main`, `develop`; merge queue | `API static checks` (one job: migration safety, SQL schema drift, security gates, OpenAPI contract, gateway routing, lint), tests, protocol-v1 compat + release binaries, Docker build; see [Tiers](#tiers) | **API CI OK** |
| Web CI (`web-ci.yml`) | PR / push to `main`, `develop`; merge queue | `API contract` (generates the contract files; for an API change compares them with the base and reports the difference), `API contract report` (the pull request comment), `Web checks` (type-check against the generated contract, ESLint, Prettier, palette drift) and `Web tests` (Vitest in three parallel shards); `next build` (push only) | **Web CI OK** |
| CodeQL (`codeql.yml`) | PR / push; merge queue; weekly (Mon 00:00 UTC) | One matrix over the languages: Go (built inside `api/`) and JavaScript/TypeScript (`web/`), one category per language. PR and merge queue: only the changed language(s). Push to `develop`/`main` and weekly: both, so each branch keeps a fresh baseline per category | **CodeQL OK** |
| All-in-one CI (`allinone-ci.yml`) | PR / push; merge queue | Builds `openctem-api`, `openctem-web` and the all-in-one `openctem` image exactly as a release does, smoke-tests them (arch, ELF, executes) and runs the all-in-one in both gateway modes against Postgres + Redis. Nothing is pushed. Merge queue and pushes only (see [Tiers](#tiers)). | **All-in-one OK** |
| Repository Security (`repo-security.yml`) | PR / push; merge queue; weekly | Betterleaks (root `.betterleaks.toml`, `.gitleaksignore`): a PR or queued group scans only its own commits (`base..head`); a push to `develop`/`main` and the weekly run scan the full history. Customer identifiers: fixed strings from the `CUSTOMER_DENYLIST` repository secret (never committed; empty = skipped with a notice) and the live LAN range outside tests, over every tracked file, printing only file:line. actionlint over the workflows | **Secret Scanning**, **Workflow Lint** |
| Docs check (`docs-check.yml`) | PR / push to `main`, `develop`; merge queue | **Docs check**: `scripts/docs_check.py` (Markdown is English, has no private addresses or internal host names, relative links and anchors resolve). **Docs links**: `scripts/check_docs_links.py` checks every `docs.openctem.io` link in code (page and `#anchor`, against a checkout of `openctemio/docs` `main`) and every `github.com/openctemio/<repo>/blob\|tree/<ref>/<path>#anchor` link (this repository from the checkout, others fetched shallowly); tests are skipped, `docs-links: ignore` skips a line. Locally: `python3 scripts/check_docs_links.py --docs ../docs --fetch-other .` | **Docs check**, **Docs links** |
| API Security (`api-security.yml`) | PR / push (`paths:` api side, see below); weekly | One job for govulncheck + Trivy (fs) + license check; Semgrep; Snyk (only if `vars.ENABLE_SNYK == 'true'`), license check, image scan (only for `main` / weekly) | — |
| Web Security (`web-security.yml`) | PR / push (`paths:` web side, see below); weekly | One job for npm audit + Trivy (fs) + ESLint security rules; Snyk (opt-in as above), image scan (only for `main` / weekly) | — |
| API Fuzz (`api-fuzz.yml`) | Nightly (03:17 UTC), manual | 10 minutes of `FuzzStrictCTIS` (the protocol-v2 results decoder); uploads a crasher artifact on failure | — |
| Docker Publish (`docker-publish.yml`) | Tag `v*`, manual | Builds, smoke-tests, publishes, signs and SBOMs every image (see [Images](#images)) | — |
| Release (`release.yml`) | Tag `v*`; dispatch on a tag | GitHub Release with `bootstrap-admin` binaries + checksums and the image pull lines | — |
| Release Train (`release-train.yml`) | Manual (a maintainer presses Run) | Proposes the version from conventional commits, picks the newest develop commit with every required check green, builds `release/vX.Y.Z` (with one commit setting `versions.yaml` `platform.release` to `vX.Y.Z`), opens and queues the release PR (see [Releases](#releases)) | — |
| Release Publish (`release-publish.yml`) | A `release/v*` PR merged into `main`; manual | Tags `vX.Y.Z` (only if `main`'s tree is the release branch's and its `versions.yaml` says `vX.Y.Z`), starts Docker Publish + Release, opens the develop and helm-charts follow-up PRs, closes the train issue | — |
| API CI `Detect API changes` step "Changelog fragments" | PR, merge queue, push (also docs-only changes) | `api/scripts/changelog.py check`: fragment format, no entry under Unreleased in `api/CHANGELOG.md`, no committed merge-conflict marker | — |
| Release Reminder (`release-reminder.yml`) | Mondays 01:00 UTC (train weeks only); manual | Opens/updates the issue "Release train vX.Y.Z" with the proposal and changelog preview | — |
| Security Gate (`security-gate.yml`) | PR (opened, pushed, labelled, retargeted); merge queue | Classifies the PR against `.github/security-paths.yml` and reviews its diff; a security-sensitive PR passes only with the `security-ack` label and no open HIGH (see [Security gate](#security-gate)). **Security gate self-test**: the gate's unit tests and the CODEOWNERS mirror | **security-gate** |
| CLA (`cla.yml`) | PR to any branch (opened, pushed, reopened); a PR comment that signs or says `recheck`; merge queue (passes) | Checks that every commit author has accepted the [Contributor License Agreement](../../../CONTRIBUTING.md#contributor-license-agreement); records new signatures in the private `openctemio/cla-signatures`. Runs in the base context and never checks out pull request code. Not required yet | **cla** |
| Release Tooling (`release-tooling.yml`) | PR / push touching `versions.yaml`, the release scripts or a versioned default | **Release scripts** (shellcheck + shell tests) and **Version consistency** (`sync-versions.sh --check`; on `release/vX.Y.Z` and on `main` right after it merges, `--release vX.Y.Z`: `platform.release` must be that version) | — |
| CI image mirror (`ci-image-mirror.yml`) | Push to `develop` changing the list or the scripts; daily (04:23 UTC); manual | Copies the third-party images CI pulls, and the digest-pinned base images of the sensor's Dockerfiles, to `ghcr.io/openctemio/mirror` (see [CI image mirror](#ci-image-mirror)) | — |

Scheduled runs (weekly security, nightly fuzz) run from the default branch, `main`.

### Required checks

Branch protection on `main` and `develop` requires exactly these seven checks.
Merges go through the GitHub merge queue (see [Merge queue](#merge-queue)); the
strict "branch must be up to date" rule is off, because the queue itself tests
each PR on top of the current base:

`API CI OK` · `Web CI OK` · `CodeQL OK` · `All-in-one OK` · `Secret Scanning` · `Workflow Lint` · `security-gate`

The four `… OK` checks are aggregator jobs (`if: always()`): they pass when every
job they depend on passed **or was skipped**, and fail when any failed or was
cancelled. The other jobs are not required individually; they reach the merge
through their aggregator. API Security and Web Security are not required.

Code-scanning result checks (CodeQL, Semgrep, Trivy alerts) are separate from
these workflow gates.

### Security gate

One human maintainer reviews every change, and most pull requests are opened by
automation under that maintainer's account, so GitHub's "required approvals"
cannot work (an author cannot approve their own pull request). The
`security-gate` check replaces them for the changes where a second look matters
most, and stays out of the way for everything else.

**What counts as security-sensitive.** A pull request that changes a file
matched by [`.github/security-paths.yml`](../../../.github/security-paths.yml):
authentication, sessions and authorization gates (middleware, auth routes and
handlers, the permission model), tenant isolation and data scope (and the
`tenantsql`/`getbyid`/`routeperm` guards), encryption, keys and signatures, the
sensor protocol (transports, mTLS, ALPN routing in the gateway, pairing), the
scope gate, web session/CSRF/proxy/header code, upload and download handlers,
the SSRF guard (`pkg/httpsec`), CI workflows and release scripts, Dockerfiles and
deployment defaults. Tests and the `tenantsql` table list count only when the
change removes lines (adding a test strengthens a guard, removing one weakens
it). A pull request is also sensitive when its added lines hit a content rule:
a migration that changes row-level security, database grants or role
permissions, or a security default in `api/internal/config/config.go`.
`.github/CODEOWNERS` mirrors the list (a generated block; the self-test fails
when they differ). Measured on the 150 pull requests merged before the gate
existed: about 40% would have been sensitive, in a period dominated by scope,
signer and sensor-protocol work.

**What the gate does** (`.github/scripts/security_gate.py`, Python standard
library only):

1. Reads the pull request's changed files through the API and classifies them.
   A non-sensitive pull request passes at once, with no comment.
2. Reviews the added lines with high-precision rules. HIGH (blocks): TLS
   verification disabled, JWT parsed unverified, `pull_request_target`,
   `write-all` tokens, an action not pinned to a SHA, event text interpolated
   into a workflow, raw HTML sinks or `eval` in the web app, row-level security
   disabled or grants to `PUBLIC` in a migration. MEDIUM (reported): outbound
   HTTP outside `pkg/httpsec`, raw client-IP headers, `os/exec` in the API,
   SQL built with `Sprintf`, wildcard CORS, privileged containers.
3. Lists new code-scanning alerts: open on the pull request's analysis
   (CodeQL, Semgrep, Trivy) and not open on the base branch. A new **high or
   critical** alert blocks. It also lists the results of the security checks on
   the head commit (govulncheck, Semgrep, Trivy, npm audit, secret scanning,
   golangci-lint with gosec).
4. Labels the pull request `security-sensitive` and posts one comment (updated
   in place) with the reasons, the findings and what is needed.
5. Passes when the pull request carries `security-ack` added by a user listed
   under `ackers` in the path list, and no HIGH finding or new high/critical
   alert is open.

**Acknowledging (the maintainer's one click).** Read the gate comment and the
diff of the listed files, then add the **`security-ack`** label. The gate
re-runs on the label and turns green; queue the pull request as usual. In the
merge queue the gate runs again (`merge_group`), finds the pull request from the
queue branch name and reads its labels and code-scanning alerts through the API.

- The ack covers the pull request's security-sensitive lines. On the label
  event the gate records a digest of them in its comment: every added and
  removed line (no context, no line numbers) of each file that makes the pull
  request sensitive, taken from the diff against the merge base. A later run
  whose digest differs removes `security-ack`; one with the same digest keeps
  it. So merging the base branch in, rebasing, or pushing changes to other
  files keeps the ack, while changing a sensitive line, adding a sensitive file
  or resolving a conflict inside one drops it. Ack again after reviewing the
  new commits. Only the comment the workflow wrote counts (a digest in anyone
  else's comment is ignored), and in the merge queue a digest that no longer
  matches blocks the group. An ack given before the gate recorded digests
  falls back to the earlier rule on its next push (a push that changes a
  sensitive file, or any force-push, removes it), and records the digest when
  it survives.
- A HIGH diff finding is resolved by changing the line, or, for a reviewed false
  positive, by a comment on the same line:
  `security-review: allow <RULE-ID> <reason>` (visible in the diff and in git
  history). A code-scanning alert is resolved by fixing it or dismissing it in
  the alert, which GitHub audits.
- Release pull requests (`release/vX.Y.Z` into `main`) are judged only on what
  the release branch adds on top of `develop`, whose commits already passed the
  gate.
- Automation working under the maintainer's account must never add
  `security-ack`: the label is the maintainer's own decision. GitHub cannot
  tell such automation from the maintainer while they share an account; once
  automation moves to its own account or GitHub App, the `ackers` list enforces
  this by itself.

**Safety of the workflow.** It runs on `pull_request` and `merge_group` only (no
`pull_request_target`). The gate script and the path list are checked out from
the **base** commit, so a pull request cannot loosen the rules it is judged by,
and no code from the pull request runs in the gate job (the diff is read as
data). Fork pull requests get a read-only token: the verdict is in the check and
the job summary, and the label and comment are skipped. The gate fails closed
on any API error, on more than 3000 changed files and on a merge-queue branch it
cannot parse. A pull request can still edit `security-gate.yml` itself, which is
the residual risk of any check defined in the repository; such a change is
`ci-release` sensitive and needs the ack like any other.

**Emergency override.** An administrator can merge a pull request whose gate is
red with **Merge without waiting for requirements (bypass rules)** (or by
removing the check from branch protection for the incident). GitHub records the
bypass in the organization audit log. Afterwards add `security-ack` to the merged
pull request, or open a follow-up issue that explains the bypass, so every
security-sensitive change carries a visible decision.

**Changing the list.** Edit `.github/security-paths.yml`, then run
`python3 .github/scripts/security_gate.py codeowners --write`, and
`python3 .github/scripts/security_gate_test.py` (the tests also fail when a
pattern matches no tracked file). The change itself is security-sensitive; it
takes effect for pull requests opened against the base after it merges.

### Path filtering

One rule set, in [`.github/scripts/changed.sh`](../../../.github/scripts/changed.sh),
decides the outputs `api` and `web` for every workflow (`docs` is informational):

| Changed path | api | web |
|--------------|-----|-----|
| Documentation: `*.md` anywhere, `api/docs/**`, `.claude/**`, `web/.claude/**` | | |
| `api/**` | ✓ | |
| `web/**` | | ✓ |
| Shared: root `Makefile`, `go.work*`, `.github/**`, `deploy/**` | ✓ | ✓ |
| Anything else (`.githooks/`) | | |

Documentation is matched first, so an RFC, a changelog fragment or a README
never starts the Go or web suites, also in the merge queue. A docs-only PR runs
Docs check, Secret Scanning, Workflow Lint, the security gate and API CI's
`changes` job (which also runs the changelog check), and the `… OK`
aggregators pass. One exception: `api/docs/configuration/environment-variables.md`
is generated and compared by a Go test (`TestEnvDocsUpToDate`), so it counts as
API code. Tests: `.github/scripts/changed.test.sh` (run by Workflow Lint).

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
| Web CI | always starts; `API contract` runs when `api` or `web`; `Web checks` when `web`, or when an API change changed the generated contract |
| CodeQL | Go when `api`, JS/TS when `web` (PR); nothing in the merge queue; both on push and weekly |
| All-in-one CI | always starts; builds when `api` or `web` (both images are built from the whole component directory), in the merge queue and on pushes only |
| Repository Security | always runs (secret scan diff-scoped on PR and merge queue) |
| API Security | `on.paths`: `api/**` + shared files, minus `**/*.md` and `api/docs/**`. Does not start at all for a web-only or docs-only change |
| Web Security | `on.paths`: `web/**` + shared files, minus `**/*.md`. Does not start at all for an API-only or docs-only change |

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
| Fast | `pull_request` | `API static checks` + `Tests (Postgres + Redis)` (the whole suite with `-race` against Postgres and Redis, so isolation tests fail on the PR; decision D-30) + `Tests (least-privilege DB role)` | `Web checks` | build skipped | changed language(s) |
| Full | `merge_group`, push to `develop`/`main` | the fast tier + `Release Binaries`; Docker build on `main` | `Web checks`; `next build` on push | images built and smoke-tested | queue: none (the PR head was analysed); push: both |

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
  reads the `toolchain` directive (currently `go1.26.9`). setup-go sets
  `GOTOOLCHAIN=local`, so this is exactly the Go that tests, CodeQL, govulncheck
  and the release binaries use. `api/Dockerfile` and `api/Dockerfile.admin-cli`
  pin their `golang:` base image separately: bump them with `go.mod`.
- **Node:** every `actions/setup-node` step uses `node-version-file: web/.nvmrc`
  (`26`), the same major as `web/Dockerfile` (`node:26-alpine`). Node 25+ ships
  its own `localStorage`; `web/src/test/setup.ts` points Vitest back at jsdom's.

### CI image mirror

Shared GitHub runner IPs exhaust the anonymous pull quotas of `public.ecr.aws`
(`toomanyrequests: Data limit exceeded`) and Docker Hub, and a job then fails
before it runs a single step. CI therefore pulls its third-party images from
GHCR, authenticated with the job's `GITHUB_TOKEN`:

- `.github/ci-images.txt` lists each image as `<source>@sha256:<digest> <name>:<tag>`.
  `ci-image-mirror.yml` copies it with `crane copy` to
  `ghcr.io/openctemio/mirror/<name>:<tag>` (manifest bytes kept, so the digest is
  the upstream one) and verifies the digest. A `docker.io/library/` source falls
  back to `public.ecr.aws/docker/library/`. The daily run re-copies anything
  missing and adds a notice when an upstream tag has moved past its pin.
- The same workflow mirrors every digest-pinned base image of the Dockerfiles
  on `main` of openctemio/sensor (`.github/scripts/ci-image-bases.sh`: only
  `public.ecr.aws/docker/library/*` and `gcr.io/distroless/*`) as
  `<name>:sha256-<hex>`, so a bumped base is mirrored within a day of its merge
  without editing the list, and never moves a tag something else pins. The
  sensor and asset-collector builds (CI, image smoke test and Docker Publish)
  swap each base for its mirror copy through buildx named contexts
  (`scripts/ci-mirror-contexts.sh` there) and fall back to the upstream while a
  digest is not mirrored yet. asset-collector is private (the job token cannot
  read it), so its bases are in the list.
- Service containers (`api-ci.yml`, `allinone-ci.yml`, `docker-publish.yml`), the
  Semgrep job container and the e2e stack (`web/e2e/ci/compose.yml`) use the
  mirror with `credentials:` from `GITHUB_TOKEN` (workflow `packages: read`).
- The mirror packages are **public**, so fork pull requests and the other
  openctemio repositories (sensor base images, the sdk-go sandbox test) pull
  them anonymously. A new package starts private: make it public once in the
  organisation's package settings; the mirror run warns while one is not.
- Jobs that build our Dockerfiles (their `FROM` lines stay on the upstream
  registries) log in first through `.github/actions/registry-login` (GHCR
  always, Docker Hub when `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` are set; both
  non-fatal), and direct `docker build` / `docker compose pull` steps run through
  `.github/scripts/retry.sh`, which retries with backoff only on registry
  rate limits and transient network errors.
- To add or bump an image: `crane digest <source>:<tag>`, edit the list (and any
  reference that pins the digest), merge; the push to `develop` mirrors it
  before the next CI run needs it.

### Workflow security

- **Every action is pinned to a full commit SHA** with a `# vX.Y.Z` comment
  (`uses: actions/checkout@<40-hex> # v7.0.1`). A tag or branch ref can be moved
  by whoever controls the action's repository, and the new code would run with
  the job's token and secrets; a SHA cannot. Workflow Lint runs
  `.github/scripts/check-action-pins.sh`, which fails on any unpinned `uses:`.
  Dependabot (`github-actions`, weekly, minor/patch grouped) bumps the SHA and
  the comment together. To add an action, resolve the release tag to its commit
  (`gh api repos/<owner>/<repo>/commits/<tag> -q .sha`) and pin that.
- **Least-privilege tokens.** Each workflow sets `permissions: contents: read`
  at the top; a job that needs more asks for it itself (for example
  `security-events: write` only on the jobs that upload SARIF, `contents: write`
  only on the job that publishes a release). The repository default for
  `GITHUB_TOKEN` is read-only as well.
- **No `pull_request_target`.** PR workflows run with the PR's read-only token
  and no secrets for fork PRs; nothing checks out a PR head with a write token.
- Downloaded tools are pinned by version and SHA-256 (betterleaks, actionlint).

### Generated contract files

The web console compiles against files generated from the Go API. **None of them
is committed** (root `.gitignore`), so two pull requests can never conflict on
them and the merge queue can test several API changes in one group:

| File | Generated from | By |
|------|----------------|----|
| `api/api/openapi/swagger.yaml` | handler `// @Router` annotations and request/response types | `make -C api swagger` (swag, pinned) |
| `api/api/openapi/routes.txt` | the router | `tools/lint/openapicontract` `TestWriteRouteManifest` |
| `web/src/config/api-route-permissions.json` | the route gates | `tests/unit/route_permission_map_test.go` |
| `web/src/config/authz-matrix.json` | the catalog, the built-in roles, the role templates, the route gates, the data-scope registry | `cmd/gen-authz-docs` ([authorization-reference.md](../architecture/authorization-reference.md)) |
| `web/src/lib/api/generated/api.types.ts` | the spec | `web/scripts/generate-api-types.sh` |

`make -C api contract` writes the first four (needs Go), `npm run
generate:api-types` in `web/` the fifth (needs Node); **`make generate`** at the
root runs both, and **`make generate-docker`** does the same in throwaway
`golang`/`node` containers when the host has only Docker
(`scripts/generate-in-docker.sh`). Run it after pulling and after changing a
handler, a route or its gate. `npm run dev/build/type-check/lint/test` refresh
the web types when the spec is newer and stop with that hint when a file is
missing (`web/scripts/ensure-generated.mjs`). Everything that builds the web
console generates first: Web CI, Web E2E, All-in-one CI, Web Security's image
scan and Docker Publish use the composite action
`.github/actions/generate-contract` before `docker build web`. The web
Dockerfile itself does not generate (its context is `web/` only): build the
image after `make generate`, as `make allinone` does.

The checks, on the generated output:

- **API CI → OpenAPI Contract** (`api/scripts/check-openapi.sh`) generates the
  spec, then checks it against the handlers and the router
  (`tools/lint/openapicontract`): every annotation is in the spec and back,
  every documented operation is routed, every route is documented or in the
  shrink-only `api/openapi/undocumented-routes.txt`, path parameter names agree
  or are in `api/openapi/param-name-drift.txt`. The test jobs generate the spec
  too, for the tests that read it (the filter-param drift test).
- **Web CI → API contract** generates the files once per run and hands them to
  `Web checks` (artifact `contract`), which builds the TypeScript types and runs
  tsc, ESLint and Vitest (including the endpoint check against `routes.txt`)
  against them. For an API change it also generates the **base's** contract
  (merge base / queue base / previous tip) and compares:
  - when the contract changed, `Web checks` runs even though `web/` did not
    change, so the web is proven to compile against the new contract;
  - `tools/openapidiff` writes the difference to the job summary and to one
    pull request comment, updated on every push (job `API contract report`, the
    only job with a write token; it runs no pull request code, and fork pull
    requests only get the summary): operations removed or added, parameters
    that became required, request/response schemas that changed
    (`tools/lint/openapischema`; descriptions and `format` are ignored because
    swag is not byte-reproducible across machines), **route gate changes** of
    the web permission map (review them as authorization changes) and
    registered routes added or removed. Breaking changes are reported, not
    failed: a reviewer decides whether one is intended.

Locally:

```bash
make generate          # every contract file (Go + Node)
make generate-docker   # the same, with only Docker
make check             # generate, the OpenAPI contract check, then tsc
```

**Deploying a bind-mounted checkout** (the API under air, the web under `next
dev`): a `git pull` that deletes or changes nothing generated still leaves the
files stale, so run `make generate-docker` (or `scripts/generate-in-docker.sh
<checkout>`) after every pull. `next dev` and air pick the new files up.

### What the API jobs check

| Job | Notes |
|-----|-------|
| *All of the rows down to Test shards are steps of one job, `API static checks`.* | |
| Migration Safety | PRs only. Flags destructive migrations against the base. |
| Migration Versions | `.github/scripts/check-migration-versions.sh` (tests: `check-migration-versions.test.sh`). Fails if two migrations share a version, and, on a PR or in the merge queue, if a migration the change adds is not above the base's highest version (golang-migrate silently skips lower versions on databases already past them). In the queue the base is `merge_group.base_sha`, so two queued PRs that picked the same number cannot both land: the second is told to renumber to max+1. A migration baseline (`NNNNNN_baseline`, RFC-053) may sit at or below the base's highest version when it is the lowest version left in the tree. On a PR, a version below the base's highest, or one a base migration also uses, is only a warning: the PR's migrations are renumbered when it is queued. Two migrations of the same PR with one version still fail. |
| Renumber this PR's clashing migrations | PR only, in `API static checks` and every DB test shard: `.github/scripts/pr-migration-renumber.sh` (tests: `pr-migration-renumber.test.sh`). CI tests the PR merged into its base; when develop has taken one of the PR's migration numbers since, the runner's copy of the PR's added migrations is renumbered above the base (in order, same width, references to the old file stems rewritten), and a byte-identical copy of a base migration (a stacked PR's inherited file) is ignored. Nothing is committed; each change is a warning annotation. The PR stays green, and the real renumber happens when the PR is queued. The merge queue and pushes never renumber: there, a clash fails `Migration Versions`. |
| SQL Schema Drift | `api/scripts/check-sql-schema.sh`: prepares every SQL statement against a migrations-only database. |
| Security Gates | `api/scripts/security-lint.sh` (checks out `sensor` and `sdk-go` alongside), tenant-scope analyzer, sensor vocabulary guard. |
| OpenAPI Contract | See above. |
| Gateway Routing | `api/deploy/gateway/smoke-test.sh` (every plane's routing against stub upstreams) + renders the production compose files. That `planes.caddy` matches the plane table is a unit test (`routes/plane` `TestGatewayPlanesFile`). |
| Test shards | `.github/scripts/go-shard.sh check` proves the test shards below cover every package and every top-level test of `tests/unit` exactly once. |
| Lint (job `API lint`, parallel to the static checks; the golangci-lint cache and the staticcheck binary are cached) | `go vet`, staticcheck, and golangci-lint v1.64.8 on **new** code only (PRs: `make lint-new` with `--new-from-rev` against `.github/scripts/effective-base.sh`). `make -C api lint-ci` runs the same locally. |
| Tests (Postgres + Redis) | PRs (when `api/` or shared files change), merge queue and pushes. `go test -race -timeout 20m` against Postgres 17 + Redis 7 service containers, split into eight parallel shards (four of `tests/unit`, which is most of the run time, and four groups of the other packages; `.github/scripts/go-shard.sh`), each with `OPENCTEM_TEST_DB_REQUIRED=1` so `internal/testdb` fails instead of skipping, then `.github/scripts/check-db-test-skips.sh` fails the job if any test skipped itself for a missing or unreachable database. |
| Tests (least-privilege DB role) | Sharded the same way (3 + 3 shards). Every event (when `api/` or shared files change). Bootstraps a fresh database with `api/deploy/postgres/least-privilege-roles.sql`, applies every migration as `openctem_migrator`, then runs the DB-backed suite as `openctem_app` (DML only). It fails if a migration needs a superuser or the API needs more than DML. See `api/docs/deployment/database-roles.md`. |
| Migrations (PostgreSQL 18) | Every event (when `api/` or shared files change). Applies every migration to a fresh PostgreSQL 18 database (the next major; the suites above run on 17), then runs the schema probes that read the catalog (`TestCheckSensorRename`). PostgreSQL 18 records each column's NOT NULL as a `pg_constraint` row (`contype = 'n'`), so a migration or probe that reads `pg_constraint` must filter on `contype`. The image comes from the CI mirror, or its upstream with the same digest until the mirror has it. |
| Release Binaries | Merge queue and pushes. Builds and uploads static linux/amd64 `cmd/server` and `cmd/bootstrap-admin` binaries. |
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
- A tag's checkout defaults to its own version: the release branch carries
  `versions.yaml` `platform.release: vX.Y.Z`, synced into
  `api/deploy/.env.example` and the compose files, so `setup.sh` on a `vX.Y.Z`
  checkout installs `vX.Y.Z`. `develop` gets the bump when `main` is merged
  back after the tag.
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
is attached to the GitHub Release, and a signed SLSA build provenance
(`actions/attest-build-provenance`, stored in the registry next to the image;
`gh attestation verify oci://<image>:<tag> --owner openctemio`).

Before the push, each image also passes the **image guard**
(`.github/scripts/image-guard.sh`), which the merge queue runs on every image
build too (`allinone-ci.yml`):

- its unpacked size stays under the component's budget (set about 15% above
  its size; raising one needs the reason in the commit message), so a stray
  `chown -R`, a duplicated binary or a toolchain left in the runtime stage
  fails instead of shipping;
- it runs as a non-root user (the gateway is the one listed exception, for
  its root-owned volumes);
- no file is setuid or setgid;
- no OS package has a HIGH or CRITICAL advisory with a fix (trivy). Advisories
  in application dependencies are printed as warnings; govulncheck and
  `npm audit` gate those in API and Web CI.

The guard reads the filesystem with `docker export`, never a shell inside the
image, so images without a shell are checked the same way.

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
The legacy names are also the only ones that hold v0.8.0 and earlier. The copy
is best effort: when it is refused the step warns and the release goes on
(v0.9.0 has no `ui` copy). The shipped Compose file and Helm values use the
current names.

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
| `CLA_SIGNATURES_TOKEN` | organization secret (required for the `cla` check) | CLA: reads and updates the signature file. Fine-grained PAT, resource owner `openctemio`, repository `cla-signatures` only, Contents read/write |
| `vars.RELEASE_TRAIN_ANCHOR` | variable (optional) | The first train Monday (`YYYY-MM-DD`, default `2026-10-05`) |

The legacy `ui` GHCR package was created by `openctemio/ui`; this repository needs
**Write** in that package's "Manage Actions access" for the legacy copy to succeed
(without it the copy step warns and the release continues).

## Troubleshooting

- **A required check stays Pending.** Something added `on.paths` to a workflow
  that carries a required check, or dropped its `merge_group` trigger; gate the
  jobs through the `changes` job instead.
- **"Generated contract files are missing" / `api.types` not found.** The
  contract files are generated, not committed: `make generate` (or `make
  generate-docker`) at the root.
- **A merge conflicts on `swagger.yaml`, `api.types.ts` or
  `api-route-permissions.json`.** A branch from before these files left git:
  take the deletion (`git rm` the file) and regenerate locally.
- **golangci-lint reports issues you didn't touch.** The PR's base is stale; rebase
  on `develop` (lint diffs against `.github/scripts/effective-base.sh`).
- **govulncheck fails on every PR at once.** A new Go stdlib CVE: bump the
  `toolchain` directive in `api/go.mod` (CI follows it) and the `golang:` base
  image in `api/Dockerfile` and `api/Dockerfile.admin-cli`.
- **Image not found after a tag.** Check the Docker Publish run; the tag must match
  `v<major>.<minor>.<patch>[-suffix]`. Images for v0.8.0 and earlier exist only
  under the legacy `api` / `ui` names.
