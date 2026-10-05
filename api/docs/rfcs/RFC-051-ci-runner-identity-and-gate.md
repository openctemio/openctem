# RFC-051: CI runner identity and the central gate

| | |
|---|---|
| Status | Accepted (decisions R-1..R-6, 2026-10-05); R1 and R2 implemented |
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

A CI run is not a sensor: it has no row in `sensors`, no heartbeat, no offline
alert and no key to rotate. The console shows it under **CI runners**.

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
  `Deprecation` and a `Link` to the exchange endpoint.
- **R-3** Runs are attached to the repository asset; they are never sensors.
- **R-4** The verdict comes from a central policy: new findings only (compared
  with the default branch) by default, accepted risk honored, secrets always
  fail. The runner's local `-fail-on` stays as the offline fallback.
- **R-6** Fork pull requests get no token unless a trust configuration says so.

## 3. Trust configurations

Per tenant (`ci_trust_configs`, migration 001058):

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
| `rules.require_protected_ref` | GitLab: only protected branches and tags |
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
   the claims, never from the request), actor, event, environment and whether
   the run is on the default branch (the repository's known default branch,
   else the configuration's).
6. A random token `octci_` + 32 bytes is returned once; only its SHA-256 is
   stored. It expires after 15 minutes. `ci_run.token_issued` is audited
   without the token.

Every refusal answers the same `401 The CI token was not accepted`.

`run_id` asks for a fresh token for a run the pipeline already holds (a long
job). It is honored only for the same tenant, repository, commit and CI run id,
before the run was evaluated and within six hours of its start; the old token
stops working. Anything else is refused and audited (`run_mismatch`).

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
run). Uploads use the ingest per-tenant rate limit and concurrency cap.

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
high severity.

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

Open points: GitHub Enterprise Server issuers (a GitHub configuration accepts
only the github.com issuer today); a merge request's target branch on GitLab is
not in the ID token, so the baseline is always the default branch.
