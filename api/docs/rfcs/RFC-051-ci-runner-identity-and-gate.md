# RFC-051: CI runner identity and the central gate

| | |
|---|---|
| Status | Accepted (decisions R-1..R-6, FI-1..FI-7, 2026-10-05; P-1..P-6, 2026-10-07); R1, R2, F1 and P1 implemented |
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
CI/CD page (never on the Sensors page: a pipeline is not a sensor): fresh or
stale against its own cadence, never offline, never dispatched.

```
CI job ──OIDC token──▶ POST /ci/oidc/exchange ──▶ trust configs (tenant) ──▶ run + octci_ token (≤15 min)
   │                                                                           │
   ├──CTIS report──▶ POST /ci/runs/{id}/results  (repository asset only) ──────┤
   └──────────────▶ POST /ci/runs/{id}/evaluate  ──▶ gate policy ──▶ pass|fail + reasons + links
```

## 2. Decisions

- **R-1** One runner for every CI system. First the sensor's one-shot mode;
  since sensor v0.11.0 the runner is `openctem-ci` (repository
  openctemio/ci: per-tool images, the GitHub Action and reusable workflow,
  GitLab templates, examples for the other providers). The sensor no longer
  runs in CI, and sdk-go `sensorkit.CIRun` has no caller.
- **R-2** CI authenticates by OIDC federation only. The `runner` sensor
  type (a sensor API key used from CI) was deprecated, then removed (decided
  2026-10-05, migration `001146`): existing runner sensors and their
  keys are deleted, the type is refused, and the CI ingest path submits
  reports as a CI run (`ingest.ProducerCIRun`), never as a sensor. **OIDC
  required for CI** (`tenants.ci_require_oidc`, migration `001120`, `GET/PUT
  /api/v1/ci/settings`, `scans:ci:read`/`scans:ci:write`): when on, the key of
  a one-shot sensor (execution mode `standalone`) is refused on every sensor
  route (v2: `403` problem `ci-oidc-required`) and audited
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
| `provider` | `github`, `gitlab`, `azure_devops`, `bitbucket`, `circleci` or `jenkins` (section 3.1) |
| `issuer` | GitHub: `https://token.actions.githubusercontent.com`, an enterprise's customized issuer `https://token.actions.githubusercontent.com/<enterprise slug>`, or a GitHub Enterprise Server `https://<host>/_services/token` (its repositories are named on that host; an internal host needs `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`). GitLab: `https://gitlab.com` or a self-managed instance's URL (https, no credentials, query or fragment). The others: section 3.1. Never a hosted provider's issuer under another provider |
| `audience` | What the job asks its provider for; default `openctem:tenant:<tenant id>`, so a token minted for one organization is useless to another. Azure Pipelines: always `api://AzureADTokenExchange`. Every other provider: must contain the tenant id. GitHub and GitLab configurations saved earlier with another audience were moved to the default by migration `ci_tenant_bound_audience`; their old audience (`legacy_audience`) is accepted for 90 days, and only for a pipeline that existed before and has not yet exchanged a token with the new audience (`ci_pipelines.audience_upgraded_at`); otherwise `legacy_audience` is refused |
| `rules.owners` | GitHub organizations or users, GitLab top-level groups (exact) |
| `rules.repositories` | `owner/name`, `owner/*` (one level), `owner/**` (any depth); the owner can never be a wildcard |
| `rules.refs` | Branches or tags (`main`, `release/*`, `refs/tags/v*`); for a pull request, its source branch |
| `rules.environments`, `rules.events` | Optional allowlists of the deployment environment and the trigger event |
| `rules.allow_fork_pull_requests` | Admit `pull_request_target`, `workflow_run` and `external_pull_request_event`, which run fork code with the base repository's identity. Off by default |
| `rules.require_protected_ref` | Only protected branches and tags. GitLab: the `ref_protected` claim. GitHub tokens carry no such claim: the configuration must list `environments` and the job must run in one of them (environments whose deployment branch rules admit only protected refs); a GitHub configuration with the switch and no environments is refused |
| `rules.workflow_refs` | Optional: admit only jobs that run one of these pipeline definitions, `<path>@<ref>` (the path exact, the ref a pattern like `refs`). GitHub: the `job_workflow_ref` claim (`acme/security/.github/workflows/scan.yml@refs/heads/main`), so an organization can trust only its central reusable workflow, and a pull request that edits or adds a workflow file is refused (`workflow_not_allowed`). GitLab: the `ci_config_ref_uri` claim (`gitlab.example.com/grp/ci//scan.yml@refs/heads/main`). At most 20 entries. Other providers' tokens do not name the definition: the rule is refused when the configuration is saved, and a token without the claim is refused |
| `default_branch` | The baseline branch when the platform does not know the repository's default branch yet. A pipeline cannot set it |
| `rules.workspace_uuid` | Bitbucket only, required: the workspace's immutable id, compared with the token's `workspaceUuid` |

A configuration must name at least one owner or repository: there is no "any
repository" trust. Several configurations may exist; the first that admits the
job wins. A configuration is only ever read for the tenant the exchange names,
by its exact issuer: two tenants may trust the same CI organization, each
with its own configuration, and nothing matches across them.

Creating or changing a trust configuration, and changing the CI settings
(`require_oidc`, which can let CI sensor keys back in), need **step-up**, like
a break-glass: they decide who may send results that the gate judges.
Deleting a configuration only withdraws trust and needs no step-up.

### 3.1 Providers

Decisions (2026-10-07): **P-1** every issuer names one CI organization,
workspace or controller, never a provider as a whole; **P-2** where the job
chooses its audience, the audience must name the tenant; **P-3** a rule on a
claim the provider never signs is refused when saved; **P-4** what the token
does not sign (a commit, a Bitbucket repository name) may come from the job
but is marked and never authorizes (break-glass, repository names already
bound); **P-5** a pull request build whose token cannot say whether it comes
from a fork counts as a fork's; **P-6** no long-lived CI secret as a
fallback for a CI system without OIDC.

| Provider | Issuer | Audience | Repository, ref, commit | Pipeline key (section 10) | Run, job | Fork / untrusted | Protected ref, events, environments |
|---|---|---|---|---|---|---|---|
| Azure Pipelines (pipeline token, no service connection) | `https://vstoken.dev.azure.com/<organization id>`; keys from its discovery document (one key set for every organization, so `org_id` must equal the issuer's) | `api://AzureADTokenExchange` (fixed) | `rpo_uri`, `rpo_ref`, `rpo_ver` | `prj_id` + `pipelines/<def_id>` | `run_id`; no job | every pull request ref | none |
| Bitbucket Pipelines | `https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc`; `workspaceUuid` must equal `rules.workspace_uuid` | tenant-bound (`oidc.audiences`) | name: the job's report, bound to `repositoryUuid` on first use; `branchName`; `commitSha` (else the job's) | `repositoryUuid` + `bitbucket-pipelines.yml` | `pipelineUuid` (attempt `pipelineRunUuid`), `stepUuid` | none (a fork's pipelines run under the fork's repository) | environments are deployment environment UUIDs (`deploymentEnvironmentUuid`); protected ref through them; no events |
| CircleCI | `https://oidc.circleci.com/org/<organization id>`; `org-id`, when present, must match | tenant-bound (`circleci run oidc get --claims`) | `vcs-origin`, `vcs-ref`; commit: the job's (`CIRCLE_SHA1`), unverified | `project-id` + `pipelines/<pipeline-definition-id>` (`.circleci/config.yml` without one) | `workflow-id`, `job-id` | every pull request ref; SSH re-runs always refused | none |
| Jenkins (OpenID Connect provider plugin) | the controller's (or folder's, or alternate) issuer, https | tenant-bound (the credential's) | claim templates `repository` (`${GIT_URL}`), `branch`, `sha` (else the job's) | hash of the repository + the job's full name without the branch | `build_number` | `PR-<n>` builds | events and environments from optional `event`, `environment` templates; no protected ref |

Bitbucket, CircleCI and Jenkins tokens carry no `jti`: the replay key is
`sha256:` + the token's SHA-256, recorded like a `jti` (section 4).

Jenkins: the claims are what the controller asserts through its claim
templates; whoever administers the controller can mint any of them, which the
trust accepts by naming the controller's issuer. A fallback for controllers
without the plugin (a tenant-issued CI credential exchanged for a run token)
was considered and not built (P-6): it would be a stored secret in CI with
the replay and theft properties of an API key, while the plugin's alternate
issuer already serves controllers the platform cannot reach.

**Preview.** `POST /api/v1/ci/trust-configs/preview` (`scans:ci:write`, ten a
minute per person) validates a draft configuration, verifies a pasted sample
token against its issuer's keys at the token's own issue time, and returns
the claims (without e-mail addresses), the normalized repository, ref,
commit and run, and the admission result. Nothing is stored and the token's
id is not recorded; an invalid draft fetches nothing.

## 4. Token exchange

`POST /api/v1/ci/oidc/exchange` `{tenant_id, id_token, run_id?, aggregate?}` (public).

1. The issuer is read from the unverified token only to pick the tenant's
   enabled configurations for it. No configuration, or a malformed token:
   refused before any verification, and nothing is written to the tenant's
   audit log (an anonymous caller cannot fill it).
2. The token is verified (`pkg/oidc.VerifyWorkloadToken`): the issuer's
   discovery document must name that exact issuer and a JWKS on the issuer's
   own host; discovery and JWKS are fetched through the SSRF-guarded client
   (`httpsec.SafeHTTPClient` + `ValidateURL`) and cached for an hour, with an
   unknown `kid` refetching at most every 30 seconds. Concurrent refreshes of
   one document wait for a single fetch; when the issuer cannot be reached
   the last discovery document and keys keep verifying for six hours, and a
   failed fetch is not repeated within 30 seconds. A token whose keys cannot
   be had (issuer unreachable past that bound, or a `kid` not yet fetched)
   answers `503 CI_ISSUER_UNAVAILABLE` with `Retry-After: 30`, before
   anything is claimed, so the job retries the same token. This tells the
   caller that the organization trusts the token's issuer and nothing more;
   algorithms RS256, RS384,
   RS512, ES256 only (never HMAC or `none`), key type must match the
   algorithm; `iss`, `aud`, `exp` (required), `nbf`, `iat` (required, not in
   the future) with one minute of leeway; lifetime at most 24 hours; `sub` and
   `jti` required (a provider that sends no `jti` is recorded by the token's
   hash, section 3.1).
3. The verified claims are normalized (GitHub: `repository`, `ref`, `sha`,
   `actor`, `run_id`, `event_name`, `environment`, `head_ref`; GitLab:
   `project_path`, `ref`, `ref_type`, `ref_protected`, `user_login`,
   `pipeline_id`, `pipeline_source`, `environment`; the others: section 3.1)
   and checked against the rules. The request's optional `commit_sha` and
   `repository` fill only what the provider does not sign (section 3.1); a
   reported commit is stored with `commit_verified = false` (migration
   `001261`) and never matches a break-glass. A refusal is audited (`ci_run.token_refused`) with the repository,
   actor, pipeline run id and the rule that refused.
4. Replay: `(iss, jti)` is recorded in `ci_oidc_replay` until the token
   expires plus an hour, with the organization, the SHA-256 of the exact
   token, the run it opened or joined and an exchange count (migration
   `002137`). The same token presented again while valid (same bytes, same
   organization) is a re-exchange: it gets a fresh upload token, added
   beside the first one, for the same run only, after every continuation
   check (repository, commit, pipeline run, attempt, job, still running,
   within six hours); at most five exchanges per token
   (`cirun.MaxTokenExchanges`), each audited (`token_exchanges`). A plain
   run's id is chosen at the first exchange, so a re-exchange after a failed
   creation makes that run and never a second one. Any other token under a
   used `(iss, jti)`, a token re-presented to another organization, or a
   record without organization is a replay, refused and audited at high
   severity. A holder of a valid token can already exchange it once and
   upload to its run; a re-exchange returns that run again and nothing
   wider, so it adds no capability, while refusing it broke honest jobs that
   lost the first answer or run `openctem-ci` more than once. The table is
   global by design and purged every ten minutes.
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

Every refusal before a trust configuration admitted the token answers the
same `401 CI_TOKEN_NOT_TRUSTED`, whose message lists what to check (tenant
id, audience, expiry, trust) without saying which failed: on a shared issuer
anyone can mint a token for any audience, and the organization's
configuration is not theirs to learn. A refusal after admission is the
organization's own pipeline and is told the reason as `401 CI_TOKEN_<reason>`
(`replay`, `replay_limit` with the first exchange time and run,
`replay_run_closed`, `run_mismatch`, `pipeline_rate`, `pipeline_cap`,
`pipeline_identity`, `aggregate_no_run_id`, `repository_binding`,
`owner_id_mismatch`, `legacy_audience`); the text names only that pipeline's
token and run, never another repository or owner id. One more exception
decided after the token verified and was admitted: a runner that
reports (User-Agent) a CI runner version below `CI_RUNNER_MIN_VERSION` gets `403
RUNNER_OUTDATED` and the refusal is audited (`runner_outdated`); the fix is on
its side. The version is self-reported: this keeps known-bad releases out, it
does not authenticate the binary. A client that reports no sensor version is
admitted and its pipeline shows the version as unknown.

The 401 says nothing, so the console says it instead. `GET
/api/v1/ci/trust-refusals` (`scans:ci:write`) lists the tenant's latest
refused exchanges from the audit log: repository, provider, ref, event, time
and rule codes, newest first, at most 50. Only verified tokens are ever
recorded. The CI/CD page shows them under Trust as "Recent refused
pipelines", each code with its reason and fix. "Connect a pipeline" on the
CI/CD page walks an administrator through four steps:
1. pick the CI system;
2. name the organization (GitHub App installations are offered);
3. create the trust and copy the snippet;
4. wait for the first run.

While waiting, it polls the runs and the refusals every 10 seconds. A refused
pipeline shows the rule and the fix at once.

`run_id` asks for a fresh token for a run the pipeline already holds (a long
job). It is honored only for the same tenant, repository, commit, CI run id,
run attempt and job (when the run recorded one), before the run was evaluated
and within six hours of its start; the old token stops working. Another job of
the same pipeline, or a re-run, gets its own run. Anything else is refused and audited (`run_mismatch`).

### 4.1 Aggregate runs

A pipeline that runs one job per scan capability in parallel (the
`openctemio/ci` GitHub reusable workflow and GitLab `all` template) reports
into ONE run and is judged once. Each job sends `aggregate: true`:

- The run is keyed by the pipeline, the provider's pipeline run id and the
  commit, all from the verified token (GitHub `run_id`, GitLab
  `pipeline_id`), **whatever the attempt or the run's status**: a pipeline run
  is the unit of evidence. The first job opens it (`ci_runs.aggregate`,
  `evidence_union`); every later job, retry and re-run attempt of the same
  pipeline run joins it. One run per key (`idx_ci_runs_pipeline_run`), so
  racing jobs land in the same run. A token without a pipeline run id is
  refused (`aggregate_no_run_id`).
- Every job gets its own 15-minute token for the run (`ci_run_tokens`, one
  hash per exchange); a job joining never invalidates another job's token.
  A continuation (`run_id`) on an aggregate run adds a token instead of
  rotating one.
- The scan jobs upload; a final job (which joins the same way) calls
  `evaluate` with the number of capability jobs that did not report as
  `scan_failures`. The verdict covers every report of the run. Once
  evaluated, the run takes no more results until a later attempt of the same
  pipeline run joins: that **re-opens** it (running again, `run_attempt`
  recorded) and the next `evaluate` judges the union of every attempt's
  reports with today's decisions. A re-run of only the gate job therefore
  never judges an empty run (it used to open a new run with no reports, which
  passed, and the commit check took that latest verdict). An exception
  approved since, or a flaky scan that succeeds on re-run, can turn it green
  without a new commit.
- A re-opened run **keeps its last verdict** until it is judged again: the
  commit check (`CommitVerdicts`) and the merged-without-a-passing-gate check
  (`PullRequestPassed`) read any run with a verdict, whatever its status. So
  retrying one scan job of a failed pipeline cannot make its failure drop out
  while another pipeline's pass decides the check.
- Capabilities the last verdict found failed (`failed_capabilities`: the
  job's capability states and those already carried) are carried on re-open
  (`carried_failed_capabilities`). Each keeps failing the run
  (`capability_failed`, state `failed_earlier`) until a report of **that**
  capability arrives. The capability comes from the tool registry by the
  report's tool name, so a report of another capability does not clear it.
  The evaluating job cannot clear it by claiming it uploaded. A runner that
  sends only a count of failed scanners (`scan_failures`, no capability
  states) has the count carried (`carried_scan_failures`) until the next
  upload.
- A run, aggregate or not, that no report was uploaded to fails
  (`no_results`): there is nothing to judge.
- A run whose gate job never ran (pipeline cancelled, gate removed, a rule
  that skipped it) would stay `running` for ever, with no verdict and nothing
  blocking a merge. A sweeper (controller `ci-sweep`, every 15 minutes, one
  replica) concludes each run still running after `MaxRunContinuation` (6 h,
  the longest a run can still get a token) with the verdict `fail` and the
  reason `not_judged`. Silence is never a pass; the uploaded findings are
  kept, and the verdict is audited as `ci_run.evaluated` with
  `reason: not_judged`. A run judged meanwhile keeps its verdict.
- The response says `aggregate: true`; a client that asked for an aggregate
  run and does not see it refuses to continue (otherwise its gate would judge
  an empty run).
- Security: joining needs a token the trust admits, like any exchange; the
  join key comes only from verified claims, so a job can join only a run of
  its own pipeline run, in its own tenant, on its own repository and commit.
  Each join is audited (`ci_run.token_issued` with `aggregate`, `joined` and
  the job id).

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

**Retries (`Idempotency-Key`).** An upload may carry an `Idempotency-Key`
header (1 to 128 printable ASCII characters). The first completed answer
(`201`) is stored for one hour under tenant + run + the key's hash (the run
comes from the upload token, so a key never reaches another run or tenant),
and a retry with the same key and body gets that answer back with
`Idempotent-Replayed: true`, without ingesting again or counting another
report. The same key with a different body is `422 IDEMPOTENCY_KEY_REUSED`;
the same key while the first request is still running is `409` with
`Retry-After`; the in-flight marker lives at least as long as the run token
(15 minutes), or until the request deadline when later. A refusal or failure
releases the key, so the retry runs again; a finished request only overwrites or
releases the key while the stored record still carries its own body hash.
The store is the shared Redis; without it, or when it fails, the upload runs
as it always did (the fingerprints still dedupe findings).
A secret finding is never stored in clear whatever the runner sends: the
runner masks it, and the server keeps only a preview of at most four
characters at each end (`vulnerability.MaskSecretPreview`), redacts the
snippet and fingerprints the value with a keyed per-tenant HMAC.

`POST /api/v1/ci/runs/{id}/baseline-diff` splits fingerprints into new and
already open on the run's baseline branch, for inline comments on new findings
only. The baseline is the pull request's base branch (GitHub's signed
`base_ref`, else the exchange's `base_ref` hint) when the repository has
scanned it and it is a release line (default, protected, or of type `main` or
`release`), else the default branch (RFC-077 G-5, `ci_runs.base_ref`).

A finding a run sees only on a branch that does not count as exposure (not
the default, a protected, a `main` or a `release` branch) is stored
branch-only: the gate and the run show it, while dashboards, SLA,
notifications and the default findings list leave it out until a counting
branch sees it. See `docs/architecture/branch-only-findings.md`.

## 6. The gate

`POST /api/v1/ci/runs/{id}/evaluate` `{scan_failures}` returns:

```json
{ "run_id": "…", "verdict": "fail", "would_fail": false,
  "policy": {"source": "repository|business_unit|tenant|default", "mode": "enforce", "fail_on_severity": "high", "new_findings_only": true, "fail_on_kev": true},
  "baseline": {"branch": "main", "known": true},
  "summary": {"evaluated": 3, "new": 1, "pre_existing": 1, "accepted": 1, "blocking": 1},
  "reasons": [{"code": "severity", "message": "severity high is at or above high", "finding_id": "…", "title": "…", "file": "db.go", "line": 42, "url": "https://…/findings/…"}],
  "links": {"run": "https://…/ci-cd?view=runs&run=…", "findings": "https://…/findings?asset_id=…"} }
```

**Expected capabilities.** A repository with a coverage expectation
(section 10.6; an empty list means sast, sca, secrets and iac) must report
each expected capability in every run. A run with no tool for one, per the
tool catalog, gets a blocking `missing_capability` reason, like a scanner
that failed. Without it, a pull request that edits its pipeline to drop a
scanner passes on silence. The tool labels are self-declared, so this does
not prove that a scan ran. It closes the "report nothing" path, and the
platform's own code scans (RFC-091) are the independent check.

Policy resolution (`ci_gate_policies`): the repository's own policy, else the
strictest of its business units' policies, else the tenant's, else the built-in
default (enforce, high and above, new findings only, KEV fails, no EPSS
threshold).

**Changing a policy** (`scans:ci:write`):

- A repository policy is listed, created, changed and deleted only for a
  repository in the caller's data scope (404 otherwise). An organization or
  business unit policy governs repositories outside a restricted data scope,
  so changing one needs an unrestricted scope (403); reading them does not.
- `fixable_only`: a dependency or image vulnerability (sca, container) fails
  on severity or EPSS only when a fixed version exists
  (`findings.remediation.fix_available`); one without a fix is listed as a
  comment-mode reason marked "no fixed version yet". KEV still fails, fixed
  or not, and code, secret and IaC findings are not affected. Off by
  default; the strictest of several policies keeps it off.
- A change that **loosens** what applies to the scope (the policy, or what the
  scope inherits when it has no enabled policy of its own) needs **step-up**,
  exactly like a break-glass, and fails closed when step-up is unavailable.
  Loosening is: `enforce` to `warn`, a higher `fail_on_severity`,
  `new_findings_only` turned on, `fail_on_kev` turned off, `fixable_only`
  turned on, a cleared or raised EPSS threshold, or a weaker capability or
  rule mode. Disabling or deleting a
  policy is judged against what the scope inherits then. Such a change is
  audited at high severity (`ci_gate_policy.loosened`, with what loosened) and
  announced to every active owner and administrator in-app and on the
  `ci.break_glass` channel event (action `policy_loosened`). A change that
  tightens the gate needs neither.

For each finding the run reported:

- **honored**: accepted risk (unexpired), `accepted_risk`, false positive,
  duplicate, or covered by a suppression rule: never blocks;
- **secret**: a new committed secret always blocks, whatever its severity; a
  secret already open on the baseline branch blocks default-branch runs and is
  a non-blocking `secret_pre_existing` note on other branches (RFC-077 G-9);
- with new-findings-only, a finding already open on the target branch does
  not block a pull request run. A **default-branch run is judged against the
  repository's gate baseline only** (section 6.2): a finding in it is
  pre-existing, every other finding is new. Without a baseline every finding
  of a default-branch run counts as new (fail closed, with a `no_baseline`
  note); without a scan of the target branch every finding of a pull request
  run counts as new;
- otherwise KEV, then the EPSS threshold, then the severity threshold.

Any scanner failure the runner reports fails the run. `warn` mode passes and
sets `would_fail`. The verdict is stored on the run and audited
(`ci_run.evaluated`). The first verdict is final: evaluating an evaluated run
returns the stored verdict unchanged and audits nothing (RFC-077 G-4); a
re-run of the pipeline gets its own run.

**Break-glass** (`ci_gate_overrides`, `scans:ci:override`): one commit (a
prefix of at least 7 hex characters) of one repository passes until the
override expires (default 24 hours, at most 7 days) or is revoked. A reason of
10 to 2000 characters is required. Creating, revoking and every use
(`ci_gate_override.used`, with the run and the blocking count) are audited at
high severity. Creating and every use also notify every active owner and
administrator in-app and the `ci.break_glass` channel event.

### 6.2 Gate baseline

A repository's **gate baseline** (`ci_gate_baselines`, `ci_gate_baseline_findings`) is the set of findings
open on its default branch when it was recorded: by the repository's **first verified default-branch run**
(once per repository), or by a person. It is the only comparison base of a default-branch run.

Why: comparing a default-branch run with "what earlier runs saw" let a failed run become its own baseline.
The first run on the default branch failed with every finding new; running the same commit again (or pushing
anything) then found every finding "already on the default branch" and passed. A failing run must never
establish a baseline, so nothing a run reports changes it.

| Rule | Where |
|---|---|
| A default-branch run: a finding is pre-existing only if its fingerprint is in the baseline and it was not reopened after the baseline was recorded | `cirun.Service.newFindings` |
| The first default-branch run of a repository that never had a baseline records one and passes on the findings it holds; the verdict says so (`baseline.established`, `baseline_established` note) and it is audited at high severity (`ci_gate_baseline.set`, source `first_run`). Only a run whose branch and commit the provider signed, never a fork; only the default branch. Once per repository: a removed baseline keeps its row (`cleared_at`), so no later run records one again | `cirun.Service.firstRunBaseline` |
| No baseline (removed): every finding of a default-branch run is new (`no_baseline` note) | same |
| A pull request run: a finding is pre-existing if it is open on the target branch and, when the target is the default branch and the repository has a baseline, also in the baseline. A finding that reached the default branch after the baseline (for example through a merge that ignored a failed gate) blocks pull requests until it is fixed, accepted or baselined | same |
| Recording a baseline (`PUT /api/v1/ci/gate-baselines/{id}`): `scans:ci:policy`, step-up, repository in the caller's data scope (404 otherwise); audited `ci_gate_baseline.set` at high severity and announced to every administrator on the break-glass channel; it replaces an earlier baseline | handler, service |
| Removing it (`DELETE`): `scans:ci:policy`; stricter, so no step-up; audited | handler, service |
| Reading it (`GET`): `scans:ci:read`, data scope | handler |
| The repository file `.openctem.yml` has no baseline setting; a CI job cannot record, change or reset a baseline | the file's schema, `RepoPolicy` |
| Secrets in the baseline still block default-branch runs (section 6) | `cirun.Evaluate` |
| The verdict names the baseline (`baseline.set_at`) and counts `new` and `pre_existing` separately | `GateBaselineView` |

The same code path judges every provider (GitHub, GitLab, Azure, Bitbucket, Jenkins); only the branch,
commit and target branch come from the provider's signed token.

### 6.1 Who sees a run

Runs, pipelines, coverage and break-glass follow the data scope of the
repository asset. A developer sees the runs of a repository when it is in
their scope, so the way to give a team its runs is to make the team (a group)
an owner of the repository asset (asset ownership refreshes
`user_accessible_assets`). Leaving the team takes the runs away. The pull
request's check and comment are visible to everyone with access to the pull
request, whatever their scope in the console. Someone outside the scope who
follows the check's link sees "This run is not available to you".

Later: a developer who pushed the commit (the token's `actor`, matched to a
verified identity linked to their console account) could see that one run
without owning the repository. This is not built. It needs the SCM identity
linking, which does not exist yet.

## 7. Runner

`openctem-ci` (openctemio/ci, `internal/platform`):

- detects the CI system and its OIDC token: GitHub Actions
  (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN`, from `permissions: id-token:
  write`), GitLab CI (an `id_tokens` variable, `OPENCTEM_ID_TOKEN` by
  default), Azure Pipelines (`System.OidcRequestUri`), Bitbucket
  (`BITBUCKET_STEP_OIDC_TOKEN`), CircleCI and Jenkins (a token minted or
  bound into `OPENCTEM_ID_TOKEN`), when `OPENCTEM_TENANT_ID` is set;
- requests the token with audience `OPENCTEM_OIDC_AUDIENCE` (default
  `openctem:tenant:<tenant id>`), exchanges it, and where the provider mints
  tokens on request (GitHub, Azure) re-exchanges with `run_id` before the run
  token expires;
- never prints a token: errors carry the HTTP status and the server's message
  only, and the session's string form redacts it;
- with `--aggregate`, every capability job joins one run and a final `gate`
  job asks for the verdict;
- prints the verdict's reasons and links and exits 0 (pass), 1 (the gate
  failed) or 2 (the scan cannot be trusted); `--fail-on` decides offline only
  when the platform verdict is unavailable.

Enforcement and pull request feedback by the platform: RFC-077.

## 8. Security

| Threat | Control |
|---|---|
| Forged, expired, not-yet-valid, wrong-issuer or wrong-audience token | Signature against the issuer's JWKS, alg allowlist, `iss`/`aud`/`exp`/`nbf`/`iat`; tests for each |
| Token for another repository, branch, event or environment | Trust rules; refusal audited with the rule |
| Fork code acting as the repository | Fork-capable events refused unless explicitly allowed; GitLab `require_protected_ref` |
| Replay of a stolen OIDC token | A token maps to one run: re-exchanges (same bytes, same organization, at most five) return that run only, audited; any other token under a used `(iss, jti)` is refused; 24-hour lifetime cap |
| Stolen run token | 15 minutes, one run, one repository, upload/evaluate only; hash stored, never the token |
| Cross-tenant | Configurations, runs, policies and overrides tenant-scoped (composite FKs to the tenant's assets); the audience names the tenant; another tenant's ids answer 404 |
| Data scope (RFC-050) | Run list and overrides filtered to the caller's repositories; by id out of scope is 404 |
| A runner inventing pipelines | Pipelines are created only at a verified, admitted exchange; key from signed ids only; per-tenant and per-configuration caps; creation audited |
| Branch, job or tool names multiplying rows | Never part of the key; tools sanitized and capped at 20 per run |
| Fork code steering the pipeline | Fork runs never refresh names, freshness, gates or cadence |
| A CI identity receiving work | Pipelines are a separate table with no key and no zone; no claim query reads them |
| Withdrawn trust | Disabling, deleting or re-pointing a configuration revokes its pipelines and its running runs' tokens at once |
| Personal data in claims | `user_email` never read; actor login only |
| Cross-tenant pipeline reads | The pipeline list and detail are tenant-scoped and follow the repository data scope; tests assert another tenant reads and lists none of the pipelines |
| A report on another asset | `REPORT_OUT_OF_SCOPE`; the `ci_run` binding can change only the repository asset |
| Baseline poisoning | The baseline branch is server-side (known default branch, else the configuration's); a run's branch comes from the token |
| A re-run of only the gate job judging an empty run and passing | Retries and re-runs re-open the pipeline run's one aggregate run (section 4.1); carried scanner failures; a run with no report fails (`no_results`) |
| A failed default-branch run becoming its own baseline (rerun whitewash) | Default-branch runs compare only with the recorded gate baseline (section 6.2); runs never write it |
| SSRF through a self-managed GitLab issuer or a Jenkins issuer | SSRF-guarded client, https only, JWKS pinned to the issuer's host; the preview validates the draft before any fetch |
| A token valid for other services (Azure's fixed audience, a CI organization's default audience) | Azure: `org_id` pinned to the issuer, one exchange per `jti`, five-minute tokens; elsewhere a tenant-bound audience is required |
| A renamed Bitbucket workspace's slug taken by someone else | `workspaceUuid` pinned in the configuration |
| A GitHub organization or GitLab namespace renamed or deleted and its name registered by someone else | The first admitted exchange pins the name to its immutable id (`repository_owner_id`, `namespace_id`) per trust configuration (`ci_trust_owner_pins`, audited); a token with the same name and another id is refused (`owner_id_mismatch`). Changing the configuration's issuer, owners or repositories drops its pins; `GET /ci/trust-configs/{id}` lists them (RFC-077 G-10) |
| A Bitbucket repository reporting as another (the name is not signed) | Rules list repository UUIDs; a name stays bound to the first UUID that used it (`repository_binding`) |
| A name that changed hands (GitHub or GitLab organization renamed or deleted and its name registered again, a repository deleted and created anew): trust rules match names | GitHub, GitLab and Bitbucket: a repository name stays bound to the repository id (`repository_id`, `project_id`, `repositoryUuid`) that first reported under it while that pipeline is not retired; another id is refused (`repository_binding`, audited) until an administrator retires the old pipeline. A rename keeps the id and is admitted |
| A job naming a commit it did not build (CircleCI) | Marked unverified; never matches a break-glass |
| A person driving a CI job interactively (CircleCI SSH re-run) | Refused |
| Pull request builds of fork code where the token cannot say so | Refused unless fork pull requests are admitted |
| JWKS fetch amplification | One-hour cache, at most one refetch per 30 seconds for an unknown `kid` or a failed fetch, concurrent refreshes collapsed into one |
| Issuer outage or key rotation breaking scans | Discovery and keys served stale up to six hours; a missing key is a retryable 503 with nothing claimed |
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
| R3 | Diff-aware scans, fingerprint stability across commits | Open (diff-aware runs: RFC-077) |
| R4 | Remote repository execution by a zoned daemon sensor | Open (needs the executor sandbox and the credential broker) |
| R5 | Signed runner image, GitHub Action and GitLab component, SARIF upload | Implemented (openctemio/ci) |
| F1 | CI pipelines: identity, JIT creation, caps, revocation, status, fleet read model (section 10, migration 001084) | Implemented |
| F2 | Sensors page: Mode and Role filters, runner rows, pipeline drawer, CI runners page folded in | Implemented, then revised (2026-10-15): pipelines live only on the CI/CD page; Sensors keeps one line linking there (FI-4) |
| F3 | Coverage (repository x capability), stale-source findings, alerts (section 10.6, migration 001099) | Implemented |
| F4, F5 | Sensor pools; policy timeouts for daemons (section 10.7) | Design only |
| P1 | Azure Pipelines, Bitbucket Pipelines, CircleCI and Jenkins trust; trust preview (section 3.1, migration 001261) | Implemented |

Open points: Azure Pipelines tokens issued through a service connection (the
Entra issuer) carry no pipeline claims and are not admitted; GitHub Enterprise Server issuers (a GitHub configuration accepts
only the github.com issuer today); a merge request's target branch on GitLab is
not in the ID token: the job reports it and it only chooses among release
lines.

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
  dispatchable: no key, no zone, no claim query reads them. Revised
  2026-10-15: each kind has one home in the console. Sensors lists the
  sensors (`GET /api/v1/sensors`), CI/CD lists the pipelines
  (`GET /api/v1/ci/pipelines`), and Sensors shows only a one-line link with
  the pipeline count. The earlier union read model, `GET /api/v1/fleet`, made
  the Sensors page list every pipeline next to the sensors, and was removed.
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
| Execution health | ok · degraded · unknown | Scanner failures the runner reported at the last evaluation; a runner older than `CI_RUNNER_MIN_VERSION` (CI runners have their own release line, never the sensor's) |

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
| `ci.runner_outdated` | pipeline | runner below `CI_RUNNER_MIN_VERSION` | on |
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
