# Finding verification plan

`GET /api/v1/findings/{id}/verification` (permission `findings:read`) answers, for one
finding, how it can be verified and what proof is recorded. The server decides it;
the console renders it in the Verification panel instead of guessing on the client.
It is advisory: the transition engine still enforces the evidence rule on every
resolve ([finding status lifecycle](finding-status-lifecycle.md#evidence-by-risk)).

Code: `internal/app/finding/verification_plan.go` (pure `buildVerificationPlan` +
`GetVerificationPlan`), `internal/app/retest/availability.go` (retest reason codes),
handler `finding_verification_plan_handler.go`.

## Answer

| Field | Meaning |
|---|---|
| `tier` | `critical` (critical, P0 or KEV), `high` (high or P1), `standard` |
| `requirement` | `second_person_or_retest`, `checklist_or_retest`, `note` |
| `second_person_required` | critical tier without a fresh confirmed-fixed retest |
| `proof_present` | the tier's evidence is recorded and fresh |
| `external_workflow` | `pentest`: the pentest module verifies it; `methods` is empty |
| `methods[]` | `kind`, `available`, `recommended`, `counts_as_proof`, `automatic`, `reason` |
| `evidence.retest` | latest completed retest: outcome, time, `fresh` |
| `evidence.checklist` | `state` (`none`, `in_progress`, `complete`), missing items, who completed it, `fresh`, `completed_by_caller` |

"Fresh" means newer than the later of the last reopen and the last sighting, the same
horizon the engine uses.

## Methods

| Kind | Available when | Counts as proof |
|---|---|---|
| `retest` | the retest service would accept one now (`Availability`); reason codes: `status_not_eligible`, `secret_needs_rotation`, `check_cannot_run`, `no_tool_rule`, `template_not_rerun`, `no_asset`, `asset_inactive`, `asset_not_network_addressable`, `asset_no_address`, `target_refused`, `no_sensor`, `no_check_sensor` | yes |
| `covered_scan` (automatic) | a repository asset (a full default-branch scan closes it), or another asset while coverage auto-resolve enforces; never secrets (`absence_not_proof_for_secrets`), pentest/manual/bug bounty/red team (`source_not_scanned`); `coverage_auto_resolve_review` / `_off` otherwise | yes (the platform closes it) |
| `safe_check` | an active network-addressable asset; not for secrets | no (reachability only) |
| `rotation_proof` | secrets only; recorded through the verification checklist | yes |
| `evidence_review` | any open finding: the checklist, signed off as the tier requires | yes |

Recommended: rotation proof for a secret; otherwise the first available of retest,
covered scan, evidence review. A closed finding answers `finding_closed` for every method.

## Security

- Tenant from the authenticated context; the finding must be in the caller's data scope
  (404 otherwise, never 403), the same check as `/transitions`.
- Reads only: the retest availability check records nothing (tested).
- Exposes the user id that completed the checklist, which members of the tenant already
  see on the checklist itself.
- Tests: `internal/app/finding/verification_plan_test.go` (per source, type, asset,
  availability and tier), `internal/app/retest` `TestRetestDB_AvailabilityReasons`,
  `internal/infra/http/routes/finding_verification_plan_db_test.go` (secret plan,
  completer told another person resolves, out of scope and cross-tenant 404).
