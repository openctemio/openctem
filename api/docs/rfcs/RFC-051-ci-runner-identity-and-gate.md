# RFC-051: CI runner identity and the central gate

| | |
|---|---|
| Status | Accepted (decisions R-1..R-6, FI-1..FI-7, 2026-10-05); R1, R2 and F1 implemented |
| Research | research/33 (runner mode), research/36 §3 (CI row), research/37 S14 (runner mode in the SDK kit) |
| Related | RFC-008 (shift-left CI scanning), RFC-023 (sensors), RFC-040 (result binding), RFC-043 (finding identity), RFC-050 (asset access model) |

## 1. Summary

A CI job no longer needs a long-lived API key. It presents the OIDC token its
CI provider (GitHub Actions, GitLab CI) issues for the job; the platform checks
it against the organization's **CI trust configurations** and returns a
**run upload token** that lives at most 15 minutes and is bound to one
**CI run** on one **repository asset**. The job uploads results with it and asks
the platform for a **verdict**: pass or fail, with reasons and links, decided by
a **central gate policy** instead of a flag in each pipeline.

A CI run is not a sensor row: it has no row in `sensors`, no heartbeat, no
offline alert and no key to rotate. Its logical identity is the **CI
pipeline** (one workflow file of one repository, section 10), listed on the
Sensors page as a sensor in **runner mode**: fresh or stale against its own
cadence, never offline, never dispatched.

```
CI job ──OIDC token──▶ POST /ci/oidc/exchange ──▶ trust configs (tenant) ──▶ run + octci_ token (≤15 min)
   │                                                                           │
   ├──CTIS report──▶ POST /ci/runs/{id}/results  (repository asset only) ──────┤
   └──────────────▶ POST /ci/runs/{id}/evaluate  ──▶ gate policy ──▶ pass|fail + reasons + links
```

## 2. Decisions

- **R-1** One binary, one SDK. The sensor's one-shot mode is the **runner**
  mode; the OIDC exchange lives in the SDK kit (sdk-go `pkg/sensorkit`), next
  to the runner entry point.
- **R-2** CI authenticates by OIDC federation; a sensor API key used by a
  `runner`-type sensor still works but every response carries
  `Deprecation` and a `Link` to the exchange endpoint. **OIDC required for
  CI** (`tenants.ci_require_oidc`, migration `001120`, `GET/PUT
  /api/v1/ci/settings`, `scans:ci:read`/`scans:ci:write`): when on, the key of
  a one-shot sensor (type `runner` or execution mode `standalone`) is refused
  on every sensor route (v2: `403` problem `ci-oidc-required`) and audited
  (`ci_run.runner_key_refused`, at most once per sensor every ten minutes); an
  unreadable setting refuses. On for every organization created after the
  migration; existing ones keep accepting keys until an administrator turns it
  on (the console shows a banner meanwhile). A daemon sensor's key copied into
  a CI job is not detectable by the platform and is not covered.
- **R-3** Runs are attached to the repository asset; they are never sensors.
- **R-4** The verdict comes from a central policy: new findings only (compared
  with the default branch) by default, accepted risk honored, secrets always
  fail. The runner's local `-fail-on` stays as the offline fallback.
- **R-6** Fork pull requests get no token unless a trust configuration says so.
- **R-7** CI runs are not scan runs: they are never dispatched, carry their
  own credential and verdict, and live in `ci_runs` (this supersedes the
  "CI = `trigger=ci`" wording of RFC-046 D2). `ci_*` names facts that exist
  because a CI workload authenticated with OIDC; facts several producers can
  report get plain names, reserved and not built: `deployments`, `artifacts`,
  `artifact_attestations`.

## 3. Trust configurations

Per tenant (`ci_trust_configs`, migration 001077):

| Field | Meaning |
|---|---|
| `provider` | `github` or `gitlab` |
| `issuer` | GitHub: `https://token.actions.githubusercontent.com` only. GitLab: `https://gitlab.com` or a self-managed instance's URL (https, no credentials, query or fragment) |
| `audience` | What the job asks its provider for; default `openctem:tenant:<tenant id>`, so a token minted for one organization is useless to another |
| `rules.owners` | GitHub organizations or users, GitLab top-level groups (exact) |
| `rules.repositories` | `owner/name`, `owner/*` (one level), `owner/**` (any depth); the owner can never be a wildcard |
| `rules.refs` | Branches or tags (`main`, `release/*`, `refs/tags/v*`); for a pull request, its source branch |
| `rules.environments`, `rules.events` | Optional allowlists of the deployment environment and the trigger event |
| `rules.allow_fork_pull_requests` | Admit `pull_request_target`, `workflow_run` and `external_pull_request_event`, which run fork code with the base repository's identity. Off by default |
| `rules.require_protected_ref` | Only protected branches and tags. GitLab: the `ref_protected` claim. GitHub tokens carry no such claim: the configuration must list `environments` and the job must run in one of them (environments whose deployment branch rules admit only protected refs); a GitHub configuration with the switch and no environments is refused |
| `default_branch` | The baseline branch when the platform does not know the repository's default branch yet. A pipeline cannot set it |

A configuration must name at least one owner or repository: there is no "any
repository" trust. Several configurations may exist; the first that admits the
job wins.

## 4. Token exchange

`POST /api/v1/ci/oidc/exchange` `{tenant_id, id_token, run_id?}` (public).

1. The issuer is read from the unverified token only to pick the tenant's
   enabled configurations for it. No configuration, or a malformed token:
   refused before any verification, and nothing is written to the tenant's
   audit log (an anonymous caller cannot fill it).
2. The token is verified (`pkg/oidc.VerifyWorkloadToken`): the issuer's
   discovery document must name that exact issuer and a JWKS on the issuer's
   own host; discovery and JWKS are fetched through the SSRF-guarded client
   (`httpsec.SafeHTTPClient` + `ValidateURL`) and cached for an hour, with an
   unknown `kid` refetching at most every 30 seconds; algorithms RS256, RS384,
   RS512, ES256 only (never HMAC or `none`), key type must match the
   algorithm; `iss`, `aud`, `exp` (required), `nbf`, `iat` (required, not in
   the future) with one minute of leeway; lifetime at most 24 hours; `sub` and
   `jti` required.
3. The verified claims are normalized (GitHub: `repository`, `ref`, `sha`,
   `actor`, `run_id`, `event_name`, `environment`, `head_ref`; GitLab:
   `project_path`, `ref`, `ref_type`, `ref_protected`, `user_login`,
   `pipeline_id`, `pipeline_source`, `environment`) and checked against the
   rules. A refusal is audited (`ci_run.token_refused`) with the repository,
   actor, pipeline run id and the rule that refused.
4. Replay: `(iss, jti)` is recorded in `ci_oidc_replay` until the token
   expires plus an hour; a second exchange of the same token is refused and
   audited at high severity. The table is global by design (a token is good
   for one exchange anywhere) and purged every ten minutes.
5. The repository asset (`github.com/<owner>/<repo>`, or
   `<gitlab host>/<project path>`) is found or created in the tenant. The run
   records repository, commit, branch, pull request, pipeline URL (built from
   the claims, never from the request), actor login (never an email), event,
   environment, the provider's pipeline run id, attempt and job id (GitHub
   `run_id`, `run_attempt`, `check_run_id`; GitLab `pipeline_id`, `job_id`)
   and whether the run is on the default branch (the repository's known default branch,
   else the configuration's).
6. A random token `octci_` + 32 bytes is returned once; only its SHA-256 is
   stored. It expires after 15 minutes. `ci_run.token_issued` is audited
   without the token.

Every refusal answers the same `401 The CI token was not accepted`, with one
exception decided after the token verified and was admitted: a runner that
reports (User-Agent) a sensor version below `SENSOR_MIN_VERSION` gets `403
RUNNER_OUTDATED` and the refusal is audited (`runner_outdated`); the fix is on
its side. The version is self-reported: this keeps known-bad releases out, it
does not authenticate the binary. A client that reports no sensor version is
admitted and its pipeline shows the version as unknown.

`run_id` asks for a fresh token for a run the pipeline already holds (a long
job). It is honored only for the same tenant, repository, commit, CI run id,
run attempt and job (when the run recorded one), before the run was evaluated
and within six hours of its start; the old token stops working. Another job of
the same pipeline, or a re-run, gets its own run. Anything else is refused and audited (`run_mismatch`).

## 5. Uploads

`POST /api/v1/ci/runs/{id}/results` with `Authorization: Bearer octci_…`. The
path id must be the token's run (else 404). A report may name only the run's
repository (else `400 REPORT_OUT_OF_SCOPE`); every finding is attached to it;
the branch, commit, default branch and pull request are the run's, from the
verified token, never the report's. The report is applied through the normal
ingest with a new binding, `ci_run` (RFC-040 §5.3): it may change the
repository asset and reopen findings on it, never another asset; it never
resolves findings on a source's say-so and never writes the global
vulnerability catalog; findings carry no sensor id. The stored fingerprints the
report sighted are recorded for the run (`ci_run_findings`, at most 100,000 per
run). Uploads use the ingest per-tenant rate limit and concurrency cap. Each
upload is audited (`ci_run.results_uploaded`: finding count, tool label, job;
never finding content). A run
accepts at most 200 reports (`409` beyond), and a pipeline may start at most
300 runs an hour (the exchange is refused beyond, audited `pipeline_rate`).
A secret finding is never stored in clear whatever the runner sends: the
runner masks it, and the server keeps only a preview of at most four
characters at each end (`vulnerability.MaskSecretPreview`), redacts the
snippet and fingerprints the value with a keyed per-tenant HMAC.

`POST /api/v1/ci/runs/{id}/baseline-diff` splits fingerprints into new and
already open on the default branch, for inline comments on new findings only.

## 6. The gate

`POST /api/v1/ci/runs/{id}/evaluate` `{scan_failures}` returns:

```json
{ "run_id": "…", "verdict": "fail", "would_fail": false,
  "policy": {"source": "repository|business_unit|tenant|default", "mode": "enforce", "fail_on_severity": "high", "new_findings_only": true, "fail_on_kev": true},
  "baseline": {"branch": "main", "known": true},
  "summary": {"evaluated": 3, "new": 1, "pre_existing": 1, "accepted": 1, "blocking": 1},
  "reasons": [{"code": "severity", "message": "severity high is at or above high", "finding_id": "…", "title": "…", "file": "db.go", "line": 42, "url": "https://…/findings/…"}],
  "links": {"run": "https://…/ci-runners/…", "findings": "https://…/findings?asset_id=…"} }
```

Policy resolution (`ci_gate_policies`): the repository's own policy, else the
strictest of its business units' policies, else the tenant's, else the built-in
default (enforce, high and above, new findings only, KEV fails, no EPSS
threshold).

For each finding the run reported:

- **honored**: accepted risk (unexpired), `accepted_risk`, false positive,
  duplicate, or covered by a suppression rule: never blocks;
- **secret**: a committed secret always blocks, whatever its age or severity;
- with new-findings-only, a finding already open on the default branch does
  not block; on the default branch itself, "new" means first detected or
  reopened by this run. Without a scan of the default branch every finding
  counts as new (fail closed, with a `no_baseline` note);
- otherwise KEV, then the EPSS threshold, then the severity threshold.

Any scanner failure the runner reports fails the run. `warn` mode passes and
sets `would_fail`. The verdict is stored on the run and audited
(`ci_run.evaluated`).

**Break-glass** (`ci_gate_overrides`, `scans:ci:override`): one commit (a
prefix of at least 7 hex characters) of one repository passes until the
override expires (default 24 hours, at most 7 days) or is revoked. A reason of
10 to 2000 characters is required. Creating, revoking and every use
(`ci_gate_override.used`, with the run and the blocking count) are audited at
high severity. Creating and every use also notify every active owner and
administrator in-app and the `ci.break_glass` channel event.

## 7. Runner

The sensor's one-shot mode, through sdk-go `pkg/sensorkit` (`CIRun`):

- detects GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`, from
  `permissions: id-token: write`) or GitLab CI (an `id_tokens` variable,
  `OPENCTEM_ID_TOKEN` by default) when `OPENCTEM_TENANT_ID` is set;
- requests the token with audience `OPENCTEM_OIDC_AUDIENCE` (default
  `openctem:tenant:<tenant id>`), exchanges it lazily at the first upload, and
  on GitHub re-exchanges with `run_id` when the run token is about to expire;
- never prints a token: errors carry the HTTP status and the server's message
  only, and the session's string form redacts it;
- after the scans, asks for the verdict, prints the reasons and links, and
  exits 1 on `fail` (2 when the gate cannot be reached and no local `-fail-on`
  is set; with `-fail-on` the local gate decides offline).

## 8. Security

| Threat | Control |
|---|---|
| Forged, expired, not-yet-valid, wrong-issuer or wrong-audience token | Signature against the issuer's JWKS, alg allowlist, `iss`/`aud`/`exp`/`nbf`/`iat`; tests for each |
| Token for another repository, branch, event or environment | Trust rules; refusal audited with the rule |
| Fork code acting as the repository | Fork-capable events refused unless explicitly allowed; GitLab `require_protected_ref` |
| Replay of a stolen OIDC token | One exchange per `(iss, jti)`; 24-hour lifetime cap |
| Stolen run token | 15 minutes, one run, one repository, upload/evaluate only; hash stored, never the token |
| Cross-tenant | Configurations, runs, policies and overrides tenant-scoped (composite FKs to the tenant's assets); the audience names the tenant; another tenant's ids answer 404 |
| Data scope (RFC-050) | Run list and overrides filtered to the caller's repositories; by id out of scope is 404 |
| A runner inventing pipelines | Pipelines are created only at a verified, admitted exchange; key from signed ids only; per-tenant and per-configuration caps; creation audited |
| Branch, job or tool names multiplying rows | Never part of the key; tools sanitized and capped at 20 per run |
| Fork code steering the pipeline | Fork runs never refresh names, freshness, gates or cadence |
| A CI identity receiving work | Pipelines are a separate table with no key and no zone; no claim query reads them |
| Withdrawn trust | Disabling, deleting or re-pointing a configuration revokes its pipelines and its running runs' tokens at once |
| Personal data in claims | `user_email` never read; actor login only |
| Cross-tenant through the fleet union | Each source tenant-scoped; the union adds no query; tests assert another tenant's fleet lists none of the pipelines |
| A report on another asset | `REPORT_OUT_OF_SCOPE`; the `ci_run` binding can change only the repository asset |
| Baseline poisoning | The baseline branch is server-side (known default branch, else the configuration's); a run's branch comes from the token |
| SSRF through a self-managed GitLab issuer | SSRF-guarded client, https only, JWKS pinned to the issuer's host |
| JWKS fetch amplification | One-hour cache, at most one refetch per 30 seconds for an unknown `kid` |
| Audit flooding | Nothing is audited before the token verifies |
| Brute force | Per-IP limit on the exchange (shared across replicas) and on run routes before the token lookup; per-run limit after |
| Token in logs | Neither token is logged or audited; tests assert the audit log carries none |

Permissions: `scans:ci:read` (owner, admin, member, viewer),
`scans:ci:write` and `scans:ci:override` (owner, admin; admin-only, refused on
custom roles).

## 9. Phases

| Phase | Content | State |
|---|---|---|
| R1 | Trust configurations, exchange, runs, uploads, CI runners view, runner OIDC | Implemented |
| R2 | Gate policies, evaluate, break-glass, runner prints the verdict | Implemented |
| R3 | Diff-aware scans, fingerprint stability across commits | Open |
| R4 | Remote repository execution by a zoned daemon sensor | Open (needs the executor sandbox and the credential broker) |
| R5 | Signed runner image, GitHub Action and GitLab component, SARIF upload | Open |
| F1 | CI pipelines: identity, JIT creation, caps, revocation, status, fleet read model (section 10, migration 001084) | Implemented |
| F2 | Sensors page: Mode and Role filters, runner rows, pipeline drawer, CI runners page folded in | Open |
| F3 | Coverage (repository x capability), stale-source findings, alerts (section 10.6, migration 001099) | API implemented; console in the follow-up PR |
| F2 | Sensors page: Mode and Role filters, runner rows, pipeline drawer, CI runners page folded in | Implemented |
| F3 | Coverage (repository x capability), stale-source findings, alerts (section 10.6) | Open |
| F4, F5 | Sensor pools; policy timeouts for daemons (section 10.7) | Design only |

Open points: GitHub Enterprise Server issuers (a GitHub configuration accepts
only the github.com issuer today); a merge request's target branch on GitLab is
not in the ID token, so the baseline is always the default branch.

## 10. Pipelines in the fleet

The fleet shows what is deployed and accountable, not each execution. A
long-running sensor is one registration with one instance (its heartbeat is
its liveness). A CI pipeline is a registration with no instance at all, only
executions (its runs). Liveness is computed per kind; nothing short-lived is
ever listed as "offline".

### 10.1 Decisions

- **FI-1** Two levels: the logical identity is listed; instances and
  executions are nested under it and expire without alerting.
- **FI-2** A pipeline's key is immutable provider ids from verified claims:
  GitHub `repository_id` + the `workflow_ref` path, GitLab `project_id` + the
  `ci_config_ref_uri` path (both without `@ref` and without the repository
  prefix, so a rename keeps the pipeline). Branch, job and tools are
  attributes of a run.
- **FI-3** Liveness per kind: heartbeat for daemons; for pipelines, freshness
  against the expected cadence. "Offline" is never used for a pipeline.
- **FI-4** Pipelines live in their own table (`ci_pipelines`) and are never
  dispatchable: no key, no zone, no claim query reads them. One read model
  (`GET /api/v1/fleet`) unifies the console.
- **FI-5** Alerts only on signals (missed schedule, coverage regression,
  opt-in failing gate, outdated runner), never per run (section 10.6).
- **FI-6** Coverage (repository x capability) is a first-class output
  (section 10.6).
- **FI-7** The same two-level model applies later to autoscaled daemons
  (sensor pools, section 10.7).

Counts (fleet header, licensing) count registrations, never runs or
instances.

### 10.2 Identity and creation

| Provider | Key (immutable) | Display (refreshed by each non-fork run) | Template (drift) |
|---|---|---|---|
| GitHub | `repository_id` + `workflow_ref` path | repository, `workflow` name | `job_workflow_ref` / `job_workflow_sha` when the job runs a reusable workflow |
| GitLab | `project_id` + `ci_config_ref_uri` path (`.gitlab-ci.yml` when absent) | project path | `ci_config_ref_uri` / `ci_config_sha` when the configuration lives in another project |

- A pipeline is created **just in time** at an exchange that a trust
  configuration admitted and whose token verified. A token without a numeric
  repository id or a usable workflow path (control characters, `.`/`..`
  segments, over 500 bytes) is refused (`pipeline_identity`, audited).
- **Caps**: 2,000 pipelines per tenant and 1,000 per trust configuration by
  default. At the cap a new pipeline is refused (`pipeline_cap`, audited);
  existing pipelines keep running. Creation is audited
  (`ci_pipeline.created`).
- **Fork runs** (only when the configuration admits fork pull requests) carry
  the upstream repository's identity and attach to its pipeline flagged
  `fork`. They never refresh its display names, never make it fresh, never set
  its gates or its cadence.
- **Labels**: the tools a run's reports declare are sanitized (`[a-z0-9._-]`,
  64 bytes, versions normalized), de-duplicated and capped at 20 per run; the
  workflow name drops control and format characters and is capped. The
  runner's version is read from its User-Agent. None is ever part of a key.
- **No personal data beyond the actor login**: GitLab's `user_email` claim is
  never read; runs keep the actor login only (covered by member erasure,
  RFC-050).
- **Rename**: the pipeline row and its history survive; it follows the
  repository asset of its latest run (a renamed repository may be a new asset
  until the inventory merges the two).
- **Backfill**: runs recorded before pipelines existed get one pipeline per
  repository asset and workflow path with the key `legacy:<asset id>`; the
  first verified run of the same asset and workflow adopts the row and writes
  the real id.

### 10.3 Status

Three dimensions, kept apart, and one badge:

| Dimension | Values | Source |
|---|---|---|
| Freshness | running · fresh · stale · archived · never | Last non-fork run against the cadence: two missed cycles of its schedule when it has scheduled runs (`event`/`pipeline_source` = `schedule`), else three times the median interval between its CI runs (jobs of one CI run count once), at least 7 and at most 30 days. Archived after 90 days idle; the next run revives it |
| Gate | passing · failing · none | Last default-branch verdict of a non-fork run (pull request verdicts shown apart) |
| Execution health | ok · degraded · unknown | Scanner failures the runner reported at the last evaluation; a runner older than `SENSOR_MIN_VERSION` |

Badge, in severity order: revoked > archived > never > failing > degraded >
stale > running > fresh. Revoked, archived and never-run pipelines are
**inactive**: hidden by default, listed on request. Hidden is never deleted:
rows, runs, findings and audit records stay.

### 10.4 Revocation

Disabling or deleting a trust configuration, or pointing it at another
issuer or audience, revokes the pipelines it admitted last and invalidates
the upload tokens of its runs still running, at once (audited,
`ci_pipeline.revoked`). The next run a configuration admits clears the
revocation.

### 10.5 API

| Endpoint | Permission |
|---|---|
| `GET /api/v1/fleet?mode=all\|daemon\|runner` (`role`, `status`, `attention`, `include_inactive`, `search`, paging) | `sensors:read` for daemon rows, `scans:ci:read` (and the scans module) for runner rows; each mode filtered by its own permission, 403 with neither |
| `GET /api/v1/ci/pipelines` (`status`, `include_inactive`, `provider`, `repository_asset_id`, `search`, paging; status counts) | `scans:ci:read` |
| `GET /api/v1/ci/pipelines/{id}` (status, branches, default-branch gate trend) | `scans:ci:read` |
| `GET /api/v1/ci/runs?pipeline_id=` | `scans:ci:read` |

Mode is `daemon` (a row in `sensors`) or `runner` (a CI pipeline); the
sensor's role (scanner, collector) is independent of the mode. The legacy v1
`type` value `runner` on a sensor row is unrelated and never reported as the
mode. Pipelines follow the repository data scope (list: SQL condition; by id
out of scope: 404).

### 10.6 Coverage and alerts (F3)

Coverage is computed per repository x capability (SAST, SCA, secrets, IaC)
from any executor: a pipeline's non-fork default-branch runs through the tools
they reported, and a daemon sensor's completed scan of the repository. A
tool's capabilities come from the tool catalog. A pipeline observation is
fresh while the pipeline is active and runs within its own cadence; a scan
observation is fresh for 30 days; anything older than 90 days counts as never.
Gaps (an expected capability that is not fresh) sort first, then uncovered
repositories, by criticality.

An administrator can mark a repository as expected to be covered, for some or
all capabilities, so "never scanned" shows as a gap. Template drift groups
active pipelines by reusable workflow (`job_workflow_ref`) and shows the
versions they run.

Findings whose only source is a stale or archived pipeline move to not
observed with the resolution `source_stale`: not fixed, not current. Only
open findings on the pipeline's repository qualify, that this pipeline's runs
reported, that no other pipeline reported in 90 days, and that nothing saw
after the pipeline's last run. Findings from people (pentest, manual, bug
bounty, red team) are never touched. A new sighting reopens them.

An administrator can retire a pipeline (a reason of 10 to 2,000 characters):
it is hidden as retired, and the same set of findings closes as resolved with
the resolution `source_retired`, in one transaction, audited with the finding
ids (each finding can be reopened). The next verified run of the pipeline
brings it back.

Alerts go through the notification outbox, once per subject while the
condition holds (`ci_alert_state`), and again only after it cleared. Never one
per run. The job runs every 15 minutes on one replica.

| Event type | Subject | Condition | Default |
|---|---|---|---|
| `ci.schedule_missed` | pipeline | scheduled and stale (two missed cycles) | on |
| `ci.coverage_regression` | repository | has active pipelines, none fresh | on |
| `ci.gate_failing` | pipeline | last default-branch verdict failed | opt-in |
| `ci.runner_outdated` | pipeline | runner below `SENSOR_MIN_VERSION` | on |
| `ci.token_refusals` | tenant | at least 20 refused token exchanges (verified tokens, so audited) in 30 minutes | on |

Revoked, retired and archived pipelines raise nothing. The job walks every
tenant with a pipeline or a trust configuration.

`ci.break_glass` (on by default) is sent when a break-glass is created and each
time it lets a failing run pass, not through the alert state; the same notice
goes in-app to every active owner and administrator of the organization.

| Endpoint | Permission |
|---|---|
| `GET /api/v1/ci/coverage` (`filter=gap\|uncovered\|covered`, `capability` with `state`, `expected`, `criticality`, `search`, paging; summary and template drift) | `scans:ci:read` |
| `PUT /api/v1/ci/coverage/expectations/{asset_id}` (`capabilities`) | `scans:ci:write` |
| `DELETE /api/v1/ci/coverage/expectations/{asset_id}` | `scans:ci:write` |
| `POST /api/v1/ci/pipelines/{id}/retire` (`reason`) | `scans:ci:write` |

### 10.7 Future work: sensor pools (F4) and policy timeouts (F5)

Design only; nothing here is implemented.

- **Pool**: an enrollment token defines a pool and its policy (minimum
  instances, instance TTL, inactivity timeout). Pods of an autoscaled
  deployment are instances with short-lived credentials derived from the pool
  enrollment; the pool is the listed registration and counts once.
- **Liveness**: live instances >= the minimum; an instance that stops
  heartbeating is dropped silently after its TTL (default one hour), never
  listed offline.
- **Goodbye on drain**: an instance draining on SIGTERM sends a signed
  goodbye; it is removed at once and its credential revoked. A crash falls back
  to the TTL.
- **Dispatch**: a pool is a dispatch target through zones and capability
  matching, like a daemon, with work split and failover across its instances.
  A CI pipeline never is.
- **Policy timeouts** for daemons: an inactivity timeout hides a silent sensor
  as inactive (not deleted); an optional unenrollment timeout revokes its
  credential.
- **Caps**: instances per pool, pools per tenant.
