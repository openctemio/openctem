# RFC-020 — Consolidate `api` + `ui` into one repository (with generated contract)

> Status: **Implemented** (cutover merged 2026-10-02, [openctemio/openctem#684](https://github.com/openctemio/openctem/pull/684))
> Scope: merge the two tightly-coupled, co-released repos `openctemio/api` (Go) and
> `openctemio/ui` (Next.js) into one. **Do NOT** merge `agent` (now `sensor`), `sdk-go`, `ctis`,
> `helm-charts` — they have genuinely independent release lifecycles.
> Origin: recurring cross-repo pain observed while shipping the 2026-09 authz work.
> The sections from "Problem" on are the proposal as approved; read
> [Outcome](#outcome-as-shipped) first for what was actually built.

## Outcome (as shipped)

The repository `openctemio/api` was **renamed** to
[`openctemio/openctem`](https://github.com/openctemio/openctem) (old URLs, issues,
PRs and releases carry over), the Go code moved to `api/`, and `openctemio/ui` was
imported under `web/` with its full history. `openctemio/ui` is being archived.

```
openctem/
  api/              # Go module github.com/openctemio/openctem/api (own go.mod, Dockerfiles)
  web/              # Next.js console (own package.json, Dockerfile)
  deploy/allinone/  # all-in-one image: API + web + api/deploy/gateway
  .github/          # one set of workflows, path-gated per component; CODEOWNERS; dependabot
  .githooks/        # repository git hooks (make hooks)
  Makefile          # thin root targets: setup, hooks, dev-api, dev-web, lint, test, check, allinone
```

Deviations from the proposal below:

| Proposal | As shipped | Why |
|----------|-----------|-----|
| New repo `openctemio/platform` | Rename `openctemio/api` → `openctemio/openctem` | Keeps the API's issues, PRs, releases, stars and GHCR package links; old URLs redirect. Name matches the product. |
| `ui/` directory | `web/` | Names what it is (the web console), not a generic "UI". |
| `contract/` directory with `permissions.yaml` + `openapi.yaml` | No `contract/`. The spec stays where the API generates it, `api/api/openapi/swagger.yaml`; `web/scripts/generate-api-types.sh` derives `web/src/lib/api/generated/api.types.ts` from it, and Web CI's `check:api-types` fails on drift | One source of truth with no copy; the vendored spec, `check:spec-vendored` and the `sync-api-spec` workflow were deleted. Permission constants are **not** generated yet (`web/src/lib/permissions/constants.ts` is still hand-maintained). |
| `go.work` at the root | No `go.work`; Go runs from `api/` with `GOWORK=off` | Nothing else to resolve: `ctis`/`sdk-go` are ordinary versioned dependencies. |
| Module path unchanged | Module path **is** `github.com/openctemio/openctem/api` (one mechanical commit, listed in `.git-blame-ignore-revs`) | Matches the new repository URL. |
| `paths:` filters + `dorny/paths-filter` | Every workflow always starts; a `changes` job runs `.github/scripts/changed.sh`; one aggregator check per workflow (`API CI OK`, `Web CI OK`, `CodeQL OK`, `All-in-one OK`) plus `Secret Scanning` and `Workflow Lint` are the required checks | `on.paths` leaves skipped required checks Pending forever; one less third-party action. |
| Keep independent image builds + tags; image names unchanged | **One `vX.Y.Z` tag releases everything** from one commit: `openctem-api`, `openctem-web`, a new all-in-one `openctem`, `migrations`, `seed`, `admin-cli` (multi-arch, cosign-signed, SBOMs). The old `ghcr.io/openctemio/api` / `ui` names receive identical copies for a two-release transition window | API and web were always deployed as a pair; one version removes the version-matrix question. |
| ui tags kept as-is | ui tags imported as `ui/vX.Y.Z`; they are history only (`v*` does not match them) | Avoids collisions with the API's `vX.Y.Z` tags. |
| — | Imported ui commit messages rewrite `#NNN` → `openctemio/ui#NNN` | A bare `#NNN` now resolves to this repository. |

Phases: P1 (migrate + path-gated CI) is done; P2 is done for API types and still
open for permission constants; P3 (archive `openctemio/ui`) is in progress. Current layout and CI:
[Repositories](../development/repositories.md), [CI/CD](../development/ci-cd.md).

## Problem

`api` and `ui` are one product shipped as two repos. That split has a real,
recurring cost — every item below was hit in a single week of work:

1. **Contract drift across the repo boundary.** The same facts are hand-maintained
   on both sides and drift silently:
   - Permission codes: Go `permission.AllPermissions()` vs `ui/src/lib/permissions/constants.ts`
     (159≡159 today — but only because a test, **AUTHZ-17**, was just written to
     police it; the test exists *only because* the two live in different repos).
   - OpenAPI ↔ handler annotations (the `undocumented-routes.txt` baseline).
   - `ctis` field parity (a whole CI job, `ctis-parity`, exists for this class).
2. **Full-stack changes are not atomic.** Almost every CTEM feature touches both
   sides and needs ordered, cross-repo merges + deploys:
   - SIEM: `api#498` + `api#499` had to merge and deploy **before** `openctemio/ui#429`
     ("works end-to-end only after api is deployed").
   - Detections: `api#504` (feed) + `openctemio/ui#449` (view) as two separate PRs/reviews.
   There is no single PR that a reviewer can read to see a feature whole, and no
   single CI run that verifies the api/ui contract together.
3. **Develop-wide breaks fan out across repos and PRs.** A new `x/crypto` CVE broke
   `govulncheck` on **every** open api PR; the fix (`#503`) had to merge, then
   **five** PRs were rebased one-by-one. A monorepo still has the break, but the
   fix + rebase is one repo, and shared tooling upgrades land once.
4. **Wrong-repo / stale-checkout friction.** Repeated "which repo is this branch
   on", stale local checkouts, force-push-to-the-right-remote overhead. One repo =
   one clone = one branch context.

None of these are fatal individually; together they are a steady tax on exactly
the full-stack, contract-shared work that is most of the roadmap.

## Proposal

Create a single repository (working name `openctemio/platform`) laid out as:

```
platform/
  api/            # unchanged Go module (own go.mod, Dockerfile)
  ui/             # unchanged Next.js app (own package.json, Dockerfile)
  contract/       # NEW: single source of shared contract + codegen
    permissions.yaml         # or derive from api's AllPermissions()
    openapi.yaml             # generated from api handler annotations
  .github/workflows/         # path-filtered CI (see below)
  go.work                    # keeps api + ctis/sdk (if vendored) resolvable
```

`agent`, `sdk-go`, `ctis`, `helm-charts` stay as separate repos:
- **sdk-go** — public Go library, independent semver, external consumers.
- **agent** — ships as its own binary/container, deployed in customer networks on
  its own cadence.
- **ctis** — the shared contract library `api` imports; keeping it separate keeps
  it a clean dependency, not a co-mingled folder.
- **helm-charts** — released via chart-releaser to `gh-pages`, own version stream.

### Design decisions

1. **Path-filtered CI.** Go workflows trigger on `api/**` + `contract/**`; Node
   workflows on `ui/**` + `contract/**`. No cross-toolchain waste; a UI-only PR
   never runs Go CI and vice-versa. GitHub Actions `paths:` filters + a small
   "changes" job (dorny/paths-filter) gate each pipeline.
2. **Generated contract replaces hand-sync.** Add a `contract` codegen step that
   emits `ui/src/lib/permissions/constants.ts` (and API TS types from
   `openapi.yaml`) from the Go source of truth, checked in CI. This **replaces**
   the AUTHZ-17 equality test with generation: drift becomes impossible, not just
   detected. Same for OpenAPI types the UI consumes.
3. **Deploy unchanged.** Two Dockerfiles, two images (`openctemio/api`,
   `openctemio/ui`) still build independently; compose/helm reference both exactly
   as today. Release tagging becomes "one commit = one deployable api+ui set",
   which is what operators already assume.
4. **`go.work` stays** for local Go resolution; the api module path is unchanged
   (`github.com/openctemio/openctem/api`) so imports don't churn — the module lives at
   `platform/api` but keeps its module path. (Alternatively rename to
   `.../platform/api`; deferred — avoid a mass import rewrite in the migration PR.)

### Migration (history-preserving, reversible)

1. `git filter-repo` (or `subtree`) to import `api/` and `ui/` into `platform/`
   **preserving full history** (commits, blame, tags).
2. Recreate branch protection, required checks, `CODEOWNERS`, and secrets on the
   new repo.
3. Consolidate Dependabot: one config, two ecosystems (`gomod` at `/api`, `npm` at
   `/ui`) — replaces the two current configs.
4. Freeze the old repos **read-only / archived** (not deleted) — instant rollback:
   if the monorepo doesn't work out, the archived repos are still authoritative and
   we split back with `filter-repo` in reverse.
5. Cut over open PRs: small number; re-open against the monorepo (or land them
   pre-migration).

Estimated one-time cost: ~1–2 days (mostly CI/branch-protection/secrets rewiring +
verifying path filters).

## Non-goals

- Merging agent/sdk-go/ctis/helm-charts (explicitly out — independent lifecycles).
- Rewriting the Go module path or the UI package name in the migration PR (deferred
  to avoid a giant diff; can be a follow-up).
- Changing deploy topology, image names, or the compose/helm layout.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Bigger clone; contributors need both toolchains | Path-filtered CI + editor workspaces; most devs already run both. |
| CI misconfiguration runs everything on every PR | Start with explicit `paths:` filters + a dashboard check that the right jobs skip. |
| History/tag loss during import | `git filter-repo` preserves history; verify blame on a sample before cutover; keep old repos archived. |
| Secrets/branch-protection missed on new repo | Checklist + a dry-run PR that exercises every workflow before archiving the old repos. |
| Two release streams collapse awkwardly | *(Proposed)* Keep independent image builds + tags. *(Shipped)* One `v*` tag for both, see Outcome. |

## Alternatives considered

- **Keep polyrepo + a shared `contract` repo.** Solves drift (1) but not atomic
  full-stack changes (2) or wrong-repo friction (4); adds a *third* repo to the
  coupled set. Rejected — less benefit, more moving parts.
- **Full monorepo of everything (incl. agent/sdk-go/ctis/helm).** Rejected —
  couples independent release lifecycles; sdk-go is a public library and agent
  ships to customer networks. The coupling that hurts is specifically api↔ui.
- **Status quo.** The recurring tax (AUTHZ-17 test, ctis-parity job, ordered
  cross-repo deploys, 5-PR rebase storms) is the cost of doing nothing.

## Recommendation

**Adopt** for api+ui. The contract-drift and non-atomic-full-stack classes are the
biggest recurring friction in day-to-day work, and a monorepo + contract codegen
converts a whole class of "compiles-but-drifted" bugs into build/CI errors — the
same philosophy as the AUTHZ-02/AUTHZ-17 gates just shipped, applied to the
api↔ui seam itself. Keep the other four repos separate.

## Decision

- [x] Consolidate **api + ui**, history-preserving: approved, shipped as `openctemio/openctem` (decisions D1–D10, 2026-10-02).
- [x] Keep separate: sensor (formerly agent), sdk-go, ctis, helm-charts (and docs).
- [x] Contract codegen: API wire types generated from the spec; permission constants still to do.

Once approved, implementation is phased: (P1) migrate + path-filtered CI green on a
dry-run; (P2) add `contract/` codegen and delete the manual sync; (P3) archive old
repos.
