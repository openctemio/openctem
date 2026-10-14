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
