# RFC-077: CI enforced gate, pull request feedback and diff-aware runs

| | |
|---|---|
| Status | Proposed (decisions G-1..G-10 adopted as recommended, 2026-10-11; owner may veto) |
| Related | RFC-051 (CI runner identity and the central gate), RFC-008 (superseded scanning path), RFC-040 (result binding), RFC-043 (finding identity), RFC-050 (asset access model) |

## 1. Summary

RFC-051 gives a CI job a short-lived identity and a central verdict. What
happens after the verdict is still up to the job: the job's exit code is the
only enforcement, and the only feedback is the job log, a job summary and,
when the customer opts in, SARIF in the code host's own code scanning. A
pull request author can turn the gate off by editing the pipeline file, and
nobody on the pull request sees which findings it introduced.

This RFC moves enforcement and feedback to the platform:

- the platform posts the verdict to the code host as a **commit check**
  that branch protection can require (the job cannot forge or skip it);
- the platform writes **one pull request comment** (new findings, upserted)
  and inline comments on changed lines, through an installed **SCM app**
  with short-lived, repository-scoped tokens;
- an **ungated merge** alert fires when a default-branch commit arrives that
  never had a passing verdict;
- the runner scans only what a pull request changed (**diff-aware runs**),
  and the gate compares with the pull request's **base branch**;
- policies get **per-capability and per-rule modes** (block, comment,
  monitor) and an optional repository file that can only tighten them.

```
CI job ── openctem-ci scan ──▶ POST /ci/runs/{id}/results ─┐
        └ openctem-ci gate ──▶ POST /ci/runs/{id}/evaluate ─┤ verdict stored
                                                            ▼
                                     decoration job (outbox) ──▶ SCM app installation token
                                                            ├─▶ check "OpenCTEM gate" on the commit
                                                            └─▶ PR comment + inline comments
```

## 2. Decisions

- **G-1** The verdict that protects a branch is the platform's check, not the
  job's exit code. Customers make the check **required**; the job's exit
  code stays for fast feedback and for code hosts without an app.
- **G-2** Decoration uses an **SCM app installation** (GitHub App; GitLab
  group access token or OAuth application where no app model exists).
  Tokens are minted per call, live at most one hour and cover only the
  installation's repositories. No personal access token is used.
- **G-3** Decoration runs **after** the verdict is stored, from the
  notification outbox, never in the evaluate request. A decoration failure
  never changes a verdict; it is retried and shown on the run.
- **G-4** **First verdict wins.** An evaluated run takes no second verdict;
  a re-run of the pipeline is a new run (RFC-051 already gives re-runs their
  own run).
- **G-5** Baseline for a pull request: its **base branch** when the platform
  has scanned it, else the repository's default branch, else no baseline
  (every finding is new, fail closed). The base branch is a job-reported
  hint; it can only choose among branches the platform scanned for the same
  repository, never widen what passes.
- **G-6** **Diff-aware runs** on pull requests by default; full runs on
  default-branch pushes and schedules. A diff run never marks findings not
  observed and never resolves (already true for the `ci_run` binding).
- **G-7** Policy modes per capability and per rule: `block` (fails the
  gate), `comment` (shown on the pull request, never fails), `monitor`
  (recorded only). Secrets default to `block`.
- **G-8** A repository file `.openctem.yml` may only **tighten** the
  effective policy and may **request** exceptions (fingerprint or rule and
  path, reason, expiry). A requested exception becomes a pending suppression
  rule and applies only after approval through the existing suppression
  workflow. An organization can forbid the file.
- **G-9** Pre-existing committed secrets: a **new** secret always fails; a
  secret already open on the base branch fails default-branch runs and is a
  `comment` on pull requests, so one historic secret does not block every
  pull request.
- **G-10** Trust hardening: a trust configuration's owners are **pinned to
  their immutable ids** (repository owner id, namespace id) on first
  admission, and an optional `workflow_refs` rule admits only pipelines that
  run listed central workflows at listed refs.

## 3. Check and comments

### 3.1 Check

Name `OpenCTEM gate` (aggregate runs: one per pipeline run). Conclusion:
`success` (pass), `failure` (fail), `neutral` (warn mode with `would_fail`),
`action_required` when a scanner failed. Summary: counts (new, pre-existing,
accepted, blocking), policy source, baseline branch, break-glass notice, link
to the run. Up to 50 annotations for new blocking findings on changed lines.
The check is posted to the commit the run's verified claims name; a run
whose commit is not verified (RFC-051 P-4) gets no check.

### 3.2 Comments

One summary comment per pull request, found by a hidden marker and updated
in place: new findings by severity (title, rule, file and line, link), a
collapsed count of pre-existing findings, the verdict. Inline review
comments only for new findings in `block` or `comment` mode on lines the
pull request changed, at most 25 per run, marked with the finding
fingerprint so a later run does not repeat them and resolves them when the
finding is gone. Text is built from platform data and escaped; scanner
messages are truncated; secret values and previews never appear.

### 3.3 Installation and binding

`scm_app_installations` (tenant-scoped): provider, host, installation id,
account (organization) id and login, repositories selection, created by,
status. An installation is bound to a tenant by an administrator
(`integrations:write` or `scans:ci:write`) whose identity on the code host is
an owner of the installing account (verified through the code host during
the install callback). A run is decorated only when its repository asset is
in the same tenant and the installation covers that repository. Two tenants
cannot bind the same installation.

## 4. Ungated merges

On a default-branch run, the platform looks up the pull request that
produced the head commit (through the installation, when present). A merged
pull request whose head commit has no passing verdict of a non-fork run
raises `ci.ungated_merge` (once per commit), with the pull request link.
Without an installation the alert is not raised.

## 5. Diff-aware runs

`openctem-ci scan --diff auto` (default on pull request events) computes the
changed files from the merge base with the base branch the CI system names
(GitHub `GITHUB_BASE_REF`, GitLab `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`,
Azure `SYSTEM_PULLREQUEST_TARGETBRANCH`, Bitbucket
`BITBUCKET_PR_DESTINATION_BRANCH`). SAST runs with a baseline commit,
secrets on the commit range, SCA on changed manifests and lock files (full
when a lock file changed). The run records `scan_mode` (`full`, `diff`) and
`base_ref`. A missing merge base falls back to a full run.

## 6. Data model

| Change | Migration |
|---|---|
| `ci_runs.base_ref`, `ci_runs.scan_mode`, `ci_runs.decoration_state` (pending, posted, failed, skipped) | additive columns with defaults |
| `ci_gate_policies.modes` JSONB (per capability and rule id) | additive, default `{}` |
| `scm_app_installations` (tenant-scoped, composite foreign keys) | new table |
| `ci_trust_owner_pins` (tenant, trust configuration, owner name, owner id, pinned at, pinned by run) | new table |

`SaveVerdict` updates only a run in `running` status (G-4).

## 7. Security

| Threat | Control |
|---|---|
| A pull request disables or edits the scan job | Required platform check (G-1); `workflow_refs` rule (G-10); ungated-merge alert |
| A job re-evaluates to flip a stored failure | First verdict wins (G-4) |
| A job claims a wider baseline | The base branch is a hint among the repository's scanned branches; no baseline fails closed |
| Comment spam or injection | One upserted summary, capped inline comments, escaped platform text only |
| Cross-tenant decoration | Installation bound to one tenant by a verified owner; repository asset must be in that tenant; installation must cover the repository |
| Leaked app credential | App private key encrypted at rest; installation tokens minted per call, at most one hour, repository-scoped; every post audited (`ci_run.decorated`) |
| Repository file loosening policy | Tighten-only; exceptions are pending suppression requests that need approval |
| Name taken over on the code host | Repository name bound to repository id (RFC-051 section 8); owner pinned to owner id (G-10) |
| SSRF through a code host URL | Hosts from the installation or integration only, SSRF-guarded client |

## 8. Phases

| Phase | Content | State |
|---|---|---|
| A | First verdict wins; base-branch baseline; secrets on pull requests (G-4, G-5, G-9) | Open |
| B | Owner id pins and `workflow_refs` rule (G-10) | Open |
| C | SCM app installations, check, summary comment, inline comments (G-1..G-3) | Open |
| D | Ungated-merge alert | Open (needs C) |
| E | Diff-aware runs in `openctem-ci` (G-6) | Open |
| F | Policy modes and `.openctem.yml` (G-7, G-8) | Open |

Not in this RFC: container image assets linking repositories to running
workloads, and platform-run pull request scans (RFC-051 R4).
