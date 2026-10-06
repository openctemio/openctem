# Repositories & how the platform fits together

**Start here if you're new to OpenCTEM as a developer.** The product you deploy
(API + web console) lives in **one repository**,
[`openctemio/openctem`](https://github.com/openctemio/openctem). The pieces that
run elsewhere or have their own consumers (the sensor, the Go SDK, the ingest
schema, the Helm charts, the public docs site) live in their own repositories
under the [`openctemio`](https://github.com/openctemio) GitHub org. This page maps
them, shows how they talk to each other, and points you at the right place to work.

> The monorepo was created on 2026-10-02 ([RFC-020](../rfcs/RFC-020-api-ui-monorepo.md)):
> `openctemio/api` was renamed to `openctemio/openctem` (old links redirect) and
> the Go code moved to `api/`; `openctemio/ui` was imported under `web/` with its
> full history and is being archived. See [History](#history) below.

## The monorepo: `openctemio/openctem`

| Directory | Stack | What it is | Image |
|-----------|-------|------------|-------|
| [`api/`](../../) | Go 1.26 · Chi · PostgreSQL 17 · Redis 7 | The **control plane**. Multi-tenant REST API, domain logic (DDD/clean architecture), auth & RBAC, persistence, migrations, background workers, admin CLI. Go module `github.com/openctemio/openctem/api`. | `ghcr.io/openctemio/openctem-api` (+ `migrations`, `seed`, `admin-cli`) |
| [`web/`](../../../web/) | Next.js 16 · React 19 · TypeScript · Tailwind v4 · shadcn/ui | The **web console** users work in. Talks only to the API. Its navigation is the CTEM loop (see the [User Guide](../user-guide/README.md)). | `ghcr.io/openctemio/openctem-web` |
| [`deploy/allinone/`](../../../deploy/allinone/) | Dockerfile + supervisor | **All-in-one image**: API + web + the `api/deploy/gateway` Caddy gateway in one container (Postgres/Redis external). | `ghcr.io/openctemio/openctem` |
| [`.github/`](../../../.github/) | GitHub Actions | One set of workflows for both components, path-gated per component. See [CI/CD](ci-cd.md). | — |
| [`.githooks/`](../../../.githooks/) | sh | Repository git hooks (`make hooks`): gofmt / type-check + lint-staged on staged files, and a commit-msg guard. | — |

Detailed docs (architecture, RFCs, deployment, this guide) live in
[`api/docs/`](../README.md); the web console's own notes are in
[`web/docs/`](../../../web/docs/README.md). Each directory has its own
`README.md` and `CLAUDE.md`.

## The separate repositories

| Repo | Language / stack | What it is |
|------|------------------|------------|
| **[`sensor`](https://github.com/openctemio/sensor)** (formerly `agent`) | Go 1.26 · GPL-3.0 | The **sensor** (binary `openctemio-sensor`) that runs *outside* the control plane (in CI, as a daemon, in a customer's network). Polls the API for work, runs scanners, reports findings back. Own release stream and images. |
| **[`sdk-go`](https://github.com/openctemio/sdk-go)** | Go 1.26 · GPL-3.0 | The **Go SDK** for anything that talks to the sensor API: task polling, finding submission, key auth, and the SSRF-guarded HTTP client (`httpsec`). The sensor is built on it. Public library with its own semver. |
| **[`ctis`](https://github.com/openctemio/ctis)** | Go · JSON Schema · Apache-2.0 | **CTIS, the CTEM Ingest Schema.** Source of truth for the wire format (assets, findings, metadata) that tools and sensors send in. JSON schemas + generated Go types; the API imports it as `github.com/openctemio/ctis`. |
| **[`helm-charts`](https://github.com/openctemio/helm-charts)** | Helm · Apache-2.0 | Official **Helm charts** (the `openctem` umbrella chart, incl. the optional bundled sensor). Released with chart-releaser on its own version stream. |
| **[`docs`](https://github.com/openctemio/docs)** | Markdown | The public **documentation site**. |
| ~~[`ui`](https://github.com/openctemio/ui)~~ | — | **Archived** (read-only). Its history now lives under `web/` in the monorepo; its old releases stay on that repository. |

## How they fit together

```
                    ┌──────────────────────────────────────┐
   Browser ───────▶ │ openctem   web/   Next.js console    │
                    │            │ REST /api/v1/*          │
                    │            ▼                         │      ┌────────────┐
                    │            api/   control plane ─────┼────▶ │ PostgreSQL │
                    │                                      ├────▶ │   Redis    │
                    └───────────────▲──────────────────────┘      └────────────┘
              sensor API            │   external connectors (Tenable, …)
     /api/v{1,2}/sensor, /agent     │
                    ┌───────────────┴───┐
                    │      sensor       │   runs scanners where the targets are
                    │ (built on sdk-go) │
                    └─────────┬─────────┘
                              │ submits findings in CTIS format
                              ▼
                        ┌───────────┐
                        │   ctis    │  ← schema both sides validate against
                        └───────────┘
```

- **`web/` → `api/`**: every screen is REST calls to `/api/v1/*`. The console
  holds no business logic it can't get from the API; authorization is always
  enforced server-side (see the [Authorization Matrix](../architecture/authorization-matrix.md)).
  The wire types the console uses are **generated** from the API's OpenAPI spec
  (`api/api/openapi/swagger.yaml` → `web/src/lib/api/generated/api.types.ts`),
  and CI fails if they drift, so a contract change and its consumer land in one PR.
- **sensor → `api/`**: the sensor authenticates with its own key and talks to
  the sensor API (protocol v2 under `/api/v2/sensor/*`; protocol v1 was retired
  on 2026-10-05), then submits results.
- **sensor uses `sdk-go`**: the SDK is the client library (auth, polling,
  submission, safe HTTP). Build your own collector on the same SDK.
- **Everyone speaks `ctis`**: ingested data must conform to the CTIS schema, so
  `ctis` is a shared dependency, not a leaf. Schema drift breaks ingestion; the
  `ctis-parity` job in sdk-go's CI guards the SDK side.
- **`helm-charts`** packages the API + web images (+ an optional sensor) for Kubernetes.

## Where to do what

| I want to… | Go to |
|------------|-------|
| Add/change an API endpoint, domain rule, or migration | `openctem` → `api/`. Read [Clean Architecture](../architecture/clean-arch.md), [Project Structure](../architecture/project-structure.md), [Migrations](migrations.md) |
| Change a screen or add a page | `openctem` → `web/`. Mirror the existing design system (tokens, shared components) |
| Change an API response the console reads | `openctem`, **one PR**: handler + `make -C api swagger` + `make api-types` (regenerates the web wire types) + the web change |
| Add a scanner or change sensor behavior | `sensor` (+ `sdk-go` if it's client-library surface) |
| Change the ingested data format | `ctis` **first** (it's the source of truth), then bump it in `api/go.mod` and `sdk-go` |
| Change how it deploys | Compose / gateway: `openctem` → [`api/deploy/`](../../deploy/); Kubernetes: `helm-charts` (see [Kubernetes](../deployment/kubernetes.md)) |
| Configure authz / add a permission | `openctem` → `api/`. The [Authorization Matrix](../architecture/authorization-matrix.md) has the recipes |
| Change public docs | `docs` |

## Running it locally

From the root of the monorepo:

```bash
git clone https://github.com/openctemio/openctem.git
cd openctem
make setup     # go mod download (api/), npm ci (web/), enable .githooks
make dev-api   # API with hot reload; needs Postgres + Redis, see Development Setup
make dev-web   # console on http://localhost:3000
```

There is no compose file or `.env.example` at the root: the API's live in
`api/` (`api/docker-compose.yml`, `api/.env.example`, `make -C api docker-dev`)
and the web's in `web/`. See [Getting Started](../getting-started.md) and
[Development Setup](setup.md). The sensor is optional locally and connects with
a key you create in the console
([Discovery → Connect an agent](../user-guide/04-discovery.md#connect-an-agent)).

## Cross-repo gotchas worth knowing early

- **One tag releases the product.** A `vX.Y.Z` tag on the monorepo publishes the
  API, web, all-in-one, migrations, seed and admin-cli images from the same
  commit; there is no separate web release any more. The sensor, sdk-go, ctis and
  helm-charts keep their own tags. See [CI/CD](ci-cd.md) and
  [Safe deploys & migrations](../deployment/safe-deploy-and-migrations.md).
- **CTIS is the contract with sensors.** `api` and `ctis` (and anything
  ingesting) must agree field-for-field. If the parity check goes red, reconcile
  the schema; don't paper over it in `api/`.
- **`api` and `sdk-go` are decoupled deliberately** (RFC-002): `api/` does not
  import `sdk-go`. Keep that boundary.
- **Run Go from `api/` with `GOWORK=off`**, which is what CI does. The monorepo
  has no `go.work`, but a parent directory's might be picked up.
- **Docs for a feature** (architecture doc, RFC, and if user-facing the
  [User Guide](../user-guide/README.md)) live in `api/docs/`. See the
  [RFC index](../rfcs/README.md).

## History

| Before 2026-10-02 | Now |
|-------------------|-----|
| `openctemio/api` (Go, repo root) | `openctemio/openctem`, `api/` (same repository, renamed; issues, PRs, releases v0.1.x–v0.8.0 and tags kept) |
| `openctemio/ui` (Next.js) | `openctemio/openctem`, `web/` (history imported); the old repo is archived |
| ui tags `vX.Y.Z` | imported as `ui/vX.Y.Z`: history only, they release nothing |
| images `ghcr.io/openctemio/api`, `…/ui` | `ghcr.io/openctemio/openctem-api`, `…/openctem-web` (the old names receive identical copies for a transition window) |
| `openctemio/agent` | `openctemio/sensor` (renamed earlier, RFC-023) |

In commit messages imported from the ui repository, `#NNN` was rewritten to
`openctemio/ui#NNN`, because a bare `#NNN` here now means an issue or PR of
`openctemio/openctem`. Write `openctemio/ui#NNN` when you cite an old ui PR.
