# Repositories & how the platform fits together

**Start here if you're new to OpenCTEM as a developer.** OpenCTEM is not one
codebase — it's a small set of repositories under the
[`openctemio`](https://github.com/openctemio) GitHub org, each with a single
clear job. This page maps them, shows how they talk to each other, and points you
at the right place to work.

> Most detailed docs (architecture, RFCs, deployment, this guide) live in the
> **`api`** repo under `docs/` because that's the platform's canonical docs home.
> Each repo also has its own `README.md`.

## The repositories

| Repo | Language / stack | What it is |
|------|------------------|------------|
| **[`api`](https://github.com/openctemio/api)** | Go 1.26 · Chi · PostgreSQL 17 · Redis 7 | The **control plane**. Multi-tenant REST API, domain logic (DDD/clean architecture), auth & RBAC, persistence, migrations, background workers. The brain. |
| **[`ui`](https://github.com/openctemio/ui)** | Next.js 16 · React 19 · TypeScript · Tailwind v4 · shadcn/ui | The **web app** users work in. Talks only to the `api`. Its navigation is the CTEM loop (see the [User Guide](../user-guide/README.md)). |
| **[`agent`](https://github.com/openctemio/agent)** | Go 1.25 · Apache-2.0 | The **scanning agent** that runs *outside* the control plane (in CI, as a daemon, in a customer's network). Polls the API for tasks, runs scanners, reports findings back. |
| **[`sdk-go`](https://github.com/openctemio/sdk-go)** | Go 1.25 · Apache-2.0 | The **Go SDK** for building anything that talks to the platform's agent API — task polling, finding submission, API-key auth, and the SSRF-guarded HTTP client (`httpsec`). The `agent` is built on it. |
| **[`ctis`](https://github.com/openctemio/ctis)** | Go · JSON Schema | **CTIS — the CTEM Ingest Schema.** The single source of truth for the on-the-wire data format (assets, findings, metadata) that tools/agents send in. JSON schemas + generated Go types. |
| **[`helm-charts`](https://github.com/openctemio/helm-charts)** | Helm | Official **Helm charts** for deploying the platform (the `openctem` umbrella chart, incl. the optional bundled agent). |

## How they fit together

```
                    ┌───────────────┐
   Browser ───────▶ │      ui       │   Next.js web app
                    └───────┬───────┘
                            │ REST /api/v1/*
                            ▼
                    ┌───────────────┐        ┌────────────┐
                    │      api      │───────▶ │ PostgreSQL │
                    │ (control      │───────▶ │   Redis    │
                    │  plane)       │        └────────────┘
                    └───────┬───────┘
              agent API ▲   │  external connectors (Wiz, Tenable, …)
     /api/v1/agent/*    │   ▼
                    ┌───────────────┐
                    │     agent     │   runs scanners where the targets are
                    │  (built on    │
                    │   sdk-go)     │
                    └───────┬───────┘
                            │ submits findings in CTIS format
                            ▼
                      ┌───────────┐
                      │   ctis    │  ← schema both sides validate against
                      └───────────┘
```

- **`ui` → `api`**: every screen is REST calls to `/api/v1/*`. The UI holds no
  business logic it can't get from the API; authorization is always enforced
  server-side (see the [Authorization Matrix](../architecture/authorization-matrix.md)).
- **`agent` → `api`**: the agent authenticates with a per-agent API key and polls
  the **agent API** (`/api/v1/agent/*`) for tasks, then submits results.
- **`agent` uses `sdk-go`**: the SDK is the client library (auth, polling,
  submission, safe HTTP). Build your own collector on the same SDK.
- **Everyone speaks `ctis`**: ingested data must conform to the CTIS schema, so
  `ctis` is a shared dependency, not a leaf. Schema drift here breaks ingestion —
  it's guarded by a parity check (see below).
- **`helm-charts`** packages `api` + `ui` (+ optional `agent`) for Kubernetes.

## Where to do what

| I want to… | Go to |
|------------|-------|
| Add/change an API endpoint, domain rule, or migration | `api` — read [Clean Architecture](../architecture/clean-arch.md), [Project Structure](../architecture/project-structure.md), [Migrations](migrations.md) |
| Change a screen or add a page | `ui` — mirror the existing design system (tokens, shared components) |
| Add a scanner or change agent behavior | `agent` (+ `sdk-go` if it's client-library surface) |
| Change the ingested data format | `ctis` **first** (it's the source of truth), then regenerate/consume in `api` |
| Change how it deploys | `helm-charts` — see [Kubernetes](../deployment/kubernetes.md) |
| Configure authz / add a permission | `api` — [Authorization Matrix](../architecture/authorization-matrix.md) has the recipes |

## Running it locally

The fastest path is Docker Compose from the `api` repo — see
[Getting Started](../getting-started.md) and [Development Setup](setup.md). That
brings up `api` + `ui` + PostgreSQL + Redis. The `agent` is optional locally and
connects with an API key you generate in the UI
([Discovery → Connect an agent](../user-guide/04-discovery.md#connect-an-agent)).

## Cross-repo gotchas worth knowing early

- **CTIS is the contract.** `api` and `ctis` (and anything ingesting) must agree
  field-for-field. A `ctis-parity` CI check exists precisely to catch drift — if
  it goes red, reconcile the schema, don't paper over it in `api`.
- **`api` and `sdk-go` were decoupled deliberately** (RFC-002) — `api` does not
  import `sdk-go`. Keep that boundary.
- **Docs live in `api/docs/`.** When you add a feature in any repo, the
  architecture doc, RFC, and (if user-facing) the [User Guide](../user-guide/README.md)
  live here — see the [RFC index](../rfcs/README.md).
- **Each repo has its own CI and its own release cadence.** Images publish on
  `v*` tags; see the [CI/CD](ci-cd.md) and [deployment](../deployment/safe-deploy-and-migrations.md)
  docs before cutting a release.
