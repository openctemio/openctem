# Code scanning: baseline, protected branches, full rescans

Design: [RFC-091](../rfcs/RFC-091-code-scanning-baseline.md). CI runs and the
gate: [RFC-051](../rfcs/RFC-051-ci-runner-identity-and-gate.md),
[RFC-077](../rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md). Branch
exposure: [branch-only-findings.md](branch-only-findings.md).

## Model

- **Settings** (`code_scan_settings`): a tenant template and per-repository overrides. They hold:
  - the protected branches (names, `*` patterns, `{default}`);
  - the capabilities (`sast`, `secrets`, `sca`, `iac`);
  - the rescan schedule;
  - routing;
  - enabled.

  A repository uses its own row, else the template, else the built-in defaults: `{default}` and `develop`, all capabilities, weekly, `auto`.
- **Baseline** (`repository_branches.baseline_*`): per branch, the state (`none`, `queued`, `running`, `done` or `failed`), the commit and time of the last completed full scan, the error, and the trigger of the last full scan.
- **Findings** stay where they always were. A full scan writes per-branch occurrences (`finding_branch_occurrences`) and reconciles them: a finding not seen by the tool on the branch is marked `auto_fixed`. Findings seen only on non-protected branches are branch-only and do not count as exposure.

## Code map

| Piece | Where |
|---|---|
| Domain (settings, validation, branch matching, states) | `pkg/domain/codescan` |
| Service (template, repository settings, status, re-baseline, audit) | `internal/app/codescan` |
| Repository (tenant-scoped; branches through the repository asset) | `internal/infra/postgres/code_scan_repository.go` |
| API (`/api/v1/ci/code-scanning/*`, CI/CD module, `scans:ci:read`/`scans:ci:write`, data scope on repositories) | `internal/infra/http/handler/ci_code_scan_handler.go`, `routes/ci.go` |
| Repository source contract | ctis `source` |
| Fetch mechanism (one commit, read-only, hardened) | sdk-go `pkg/source` |

## Authorization and isolation

- Reading needs `scans:ci:read`; changing settings, resetting them and re-baselining need `scans:ci:write`. Each change is audited: `code_scan_settings.updated` and `code_scan.rebaseline_requested`.
- Per-repository routes answer 404 for a repository outside the caller's data scope, and the list is filtered in SQL.
- `repository_branches` has no tenant column. Every query joins the repository asset and filters on its tenant, and per-repository settings reference the asset through a `(tenant_id, asset_id)` foreign key.

## Data flows (taint traces)

A SAST finding can carry the path tainted data takes from a source to the sink (`ctis` `data_flow`). Every producer reaches the same storage:

- **Producers.** The ctis importer maps semgrep and opengrep `dataflow_trace` and SARIF `codeFlows` (the first thread flow with a location) to `data_flow`. The sensor's semgrep scanner sends `data_flow` itself. `ctis.NormalizeDataFlow` bounds every trace (100 steps), makes paths repository-relative (absolute paths of the scanning machine are dropped), and masks credentials in step snippets.
- **Storage.** `finding_data_flows` holds one row per flow and `finding_flow_locations` one row per step (`source`, `intermediate`, `sanitizer`, `sink`, in step order). Ingest matches each trace to the finding by fingerprint within the ingesting tenant, for new and re-sighted findings alike (`FindingProcessor.persistDataFlows`, `DataFlowRepository.ReplaceDataFlows`). The trace is normalized first (`vulnerability.NormalizeDataFlows`: at most 50 flows of 100 steps, column limits, closed sets), then hashed (`trace_hash`, SHA-256 over the stored values).
- **Re-scans.** The same trace leaves the rows alone. A changed trace replaces the finding's flows in one transaction, serialized per finding with an advisory lock; the tenant and the stored hash are re-checked under the lock. A report without a trace keeps the stored one: no trace is not evidence that the path is gone.
- **Identity.** The trace never feeds the fingerprint. A finding reported with, without or with a different trace stays the same finding.
- **Reads.** `GET /api/v1/findings/{id}` returns `data_flow` and `GET /api/v1/findings/{id}/dataflows` the traces, both behind the finding's own gate: tenant, data scope and pentest campaign membership; out of scope answers 404. The flow tables have no tenant column, so every query joins `findings` and filters on its tenant.
