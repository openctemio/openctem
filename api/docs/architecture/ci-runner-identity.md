# CI runner identity and the CI gate

> Design: [RFC-051](../rfcs/RFC-051-ci-runner-identity-and-gate.md). How to
> connect a pipeline: [how-to/connect-ci-pipelines.md](../how-to/connect-ci-pipelines.md).
> The scanning path in CI itself: [shift-left-ci-scanning.md](shift-left-ci-scanning.md).

## Components

```mermaid
graph TD
  subgraph CI["CI job (GitHub Actions / GitLab CI)"]
    R["sensor, runner mode<br/>sdk-go sensorkit.CIRun"]
    P["CI provider OIDC token"]
    P --> R
  end
  subgraph API["api"]
    H1["handler.CIRunnerHandler<br/>Exchange · AuthenticateRun · UploadResults · Evaluate"]
    H2["handler.CIAdminHandler<br/>trust configs · runs · policies · overrides"]
    S["app/cirun.Service"]
    V["pkg/oidc.VerifyWorkloadToken<br/>(SSRF-guarded discovery + JWKS)"]
    I["app/ingest.IngestForCIRun<br/>binding ci_run"]
    G["pkg/domain/cirun.Evaluate"]
    DB[("ci_trust_configs · ci_runs · ci_run_findings<br/>ci_oidc_replay · ci_gate_policies · ci_gate_overrides")]
  end
  R -- "POST /ci/oidc/exchange" --> H1
  R -- "Bearer octci_: results, evaluate" --> H1
  H1 --> S
  H2 --> S
  S --> V
  S --> I
  S --> G
  S --> DB
```

| Piece | Where |
|---|---|
| Domain: trust rules, claims parsing, run, gate evaluation | `pkg/domain/cirun` |
| Workload token verification | `pkg/oidc/workload.go` |
| Service: exchange, continuation, upload scoping, policy resolution, evaluate, administration | `internal/app/cirun` |
| Ingest entry point and the `ci_run` binding | `internal/app/ingest/ci_run.go`, `binding.go` |
| Repository | `internal/infra/postgres/ci_run_repository.go` |
| Routes and their chains | `internal/infra/http/routes/ci.go` |
| Console | `web/src/features/ci-runners` (`/ci-runners`, `/settings/scanning/ci`) |
| Pipelines: identity, status, fleet rows | `pkg/domain/cirun/pipeline.go`, `internal/app/cirun/pipelines.go`, `internal/infra/postgres/ci_pipeline_repository.go`, `handler/ci_pipeline_handler.go` |
| Fleet read model (`GET /api/v1/fleet`) | `handler/fleet_handler.go`, `handler/sensor_fleet.go`, `routes/fleet.go` |
| Coverage, expectations, retirement | `pkg/domain/cirun/coverage.go`, `internal/app/cirun/coverage.go`, `internal/infra/postgres/ci_coverage_repository.go`, `handler/ci_coverage_handler.go` |
| Alerts and stale sources (every 15 minutes, one replica) | `internal/app/cirun/alerts.go`, `internal/infra/controller/ci_alerts.go` |
| Migration | `001077_ci_runner_identity`, `001084_ci_pipelines`, `001099_ci_coverage_alerts` |

## Request chains

| Route | Chain |
|---|---|
| `POST /api/v1/ci/oidc/exchange` | per-IP token-exchange limit (60/min, shared store) → handler (32 KB body, unknown fields refused) |
| `POST /api/v1/ci/runs/{id}/results` | per-IP limit → `AuthenticateRun` (token hash lookup, path id = run) → per-run limit → ingest per-tenant limit and concurrency cap → 50 MB body → decompression |
| `POST /api/v1/ci/runs/{id}/baseline-diff`, `/evaluate` | per-IP limit → `AuthenticateRun` → per-run limit |
| `/api/v1/ci/{trust-configs,runs,pipelines,gate-policies,gate-overrides}` | session tenant chain → `scans` module → `scans:ci:*` |
| `GET /api/v1/fleet` | session tenant chain → `sensors:read` or `scans:ci:read`; the handler lists each mode under its own permission (runner rows also need the `scans` module) |

## Data model

- `ci_trust_configs`: per tenant; `rules` JSONB (owners, repositories, refs,
  environments, events, fork and protected-ref switches).
- `ci_runs`: per tenant, composite FK to the tenant's repository asset
  (cascade). Token hash (unique) and expiry; verdict and its JSON detail; the
  provider's run id, attempt and job id (`external_job_id`, migration
  `001110`) from the verified claims.
- `ci_run_findings`: `(run_id, fingerprint)`; the gate joins it to `findings`
  of the run's asset.
- `ci_oidc_replay`: `(issuer, jti)`, global.
- `ci_gate_policies`: one per `(tenant, scope_type, scope_id)`.
- `ci_gate_overrides`: per tenant, composite FK to the repository asset.
- `ci_pipelines`: per tenant, unique `(tenant, provider, issuer,
  external_repo_id, workflow_path)`, composite FK to the repository asset
  (cascade; moved by asset merge). Holds the run summary the status is
  computed from (last run, fork run, default-branch and pull request
  verdicts, scanner failures, runner version, tools, median and schedule
  intervals, revocation, retirement). `ci_runs.pipeline_id` (composite FK)
  links each run.
- `ci_coverage_expectations`: one per `(tenant, repository asset)`, composite
  FK to the asset (cascade; moved by asset merge); the expected capabilities
  (empty = all four).
- `ci_alert_state`: one row per `(tenant, subject, kind)` while the alert's
  condition holds; the notification is sent when the row is created.

### Exchange and pipeline flow

```mermaid
sequenceDiagram
  participant J as CI job
  participant S as cirun.Service
  participant DB as Postgres
  J->>S: OIDC token
  S->>S: verify, admit (trust rules)
  S->>S: PipelineKeyFromClaims (repository id + workflow path)
  S->>DB: claim jti
  S->>DB: UpsertPipeline (advisory lock per tenant, caps, legacy adoption)
  S->>DB: CreateRun (pipeline_id, runner version)
  S->>DB: RefreshPipeline (summary from runs; fork runs excluded)
  S-->>J: run + octci_ token
```

## Invariants

- A run never creates a sensor row and has no heartbeat; offline alerts never
  see it. Its pipeline is listed in the fleet in runner mode and is never
  offline and never dispatched.
- A pipeline is created only at a verified, admitted exchange, keyed by signed
  immutable ids; branch, job and tool labels never create rows.
- Every fleet source is tenant-scoped and the runner rows follow the data
  scope; the fleet handler adds no query of its own.
- The run's branch, commit, pull request and pipeline URL come from the
  verified token; the report's own branch information is replaced.
- A run's report changes only its repository asset; the baseline branch is
  decided server-side.
- Neither the CI provider's token nor the run token is logged, stored (only the
  run token's SHA-256) or audited.
- Coverage lists only repositories in the caller's data scope; marking a
  repository or retiring a pipeline out of scope is a 404. The alert job lists
  tenants once and every later query is tenant-scoped.
- Stale marking and retirement touch only open findings on the pipeline's
  repository that this pipeline alone reported and nothing saw after its last
  run; findings from people (pentest, manual, bug bounty, red team) are never
  touched. A new sighting reopens a not-observed finding.
- A run token is renewed only for the job it was issued to (same run id,
  attempt and job id).
- Audited: exchange (`ci_run.token_issued`/`token_refused`), each upload
  (`ci_run.results_uploaded`), the verdict (`ci_run.evaluated`) and each
  break-glass create, revoke and use. The actor is `ci:<provider>:<login>`.
- Refusals are uniform to the caller and detailed in the audit log only after
  the token verified.
