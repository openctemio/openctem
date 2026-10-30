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
| `covered_scan` (automatic) | a repository asset (a full default-branch scan closes it), or another asset while coverage auto-resolve enforces and the organization's [closing mode](#closing-mode) lets a covered scan close this finding (`coverage_auto_resolve_review` when it would propose, `_off` when the mode is off); never secrets (`absence_not_proof_for_secrets`), pentest/manual/bug bounty/red team (`source_not_scanned`); `coverage_auto_resolve_review` / `_off` otherwise | yes (the platform closes it) |
| `safe_check` | an active network-addressable asset; not for secrets | no (reachability only) |
| `rotation_proof` | secrets only; recorded through the verification checklist | yes |
| `evidence_review` | any open finding: the checklist, signed off as the tier requires | yes |

Recommended: rotation proof for a secret; otherwise the first available of retest,
covered scan, evidence review. A closed finding answers `finding_closed` for every method.

## Closing mode

Each organization chooses how the platform closes findings without a person
(`GET|PUT /api/v1/organization/settings/closure`, owner or administrator; section
`closure` of the organization settings, `pkg/domain/tenant/closure_settings.go`):

| `mode` | Meaning |
|---|---|
| `auto` | the platform closes per the tier rule below. New organizations start here |
| `review` | every close the platform would make becomes a proposal for a person. An organization created before the setting existed has no mode and reads as `review` |
| `off` | only a person closes findings |

`critical_auto_close` (default false) lets a plain covered scan close critical, P0 and
KEV findings in `auto` mode.

One pure rule, `vulnerability.DecideClosure(mode, tier, method, flaky, criticalAutoClose)`
(`pkg/domain/vulnerability/closure_decision.go`), returns `close`, `propose` or `keep`.
In `auto`:

| Method | Standard | High / P1 | Critical / P0 / KEV |
|---|---|---|---|
| verified retest, claimed fix + qualified scan, default-branch CI run, source-reported fix | close | close | close |
| covered scan, no fix claimed | close | close | propose (close with `critical_auto_close`) |
| asset confirmed gone (`obsolete_asset`), check marked flaky on the asset | propose | propose | propose |

`review` turns every `close` into `propose`; `off` keeps every finding open. An unknown
mode or method never closes.

**Platform ceiling.** `INGEST_COVERAGE_AUTO_RESOLVE` stays the operator's switch:
`off` and `dry_run` (default) close nothing, whatever the organization chose; `enforce`
(alias `tenant`) applies the closing mode. Today the rule runs in front of coverage
auto-resolve (`internal/app/ingest/closure_mode.go`): the evaluator reads the
organization's policy once per run, the tiers of the stale findings in one tenant-scoped
query (`FindingRiskTiers`), resolves only `close`, and records `propose` on the ingest
receipt (`coverage.note = review`) and in an `ingest.coverage_auto_resolve_dry_run`
audit entry with `decision = review`. A held run (blinding guard), template drift and
secrets behave as before: a held run never closes. When the policy or the tiers cannot
be read, nothing closes (review; tiers read as critical). The verification plan's
`covered_scan` method uses the same rule. A store of proposals with a review queue
comes next; until then a proposal is only recorded.

**Who may change it.** Owner or administrator (`RequireAdmin`). A change that loosens
the policy (`off` to `review` or `auto`, `review` to `auto`, `critical_auto_close` on)
needs a recent re-authentication, is audited `tenant.closure_updated` at high severity
and notifies every owner and administrator. Turning `critical_auto_close` on is for the
organization owner only (403 for an administrator). Tightening is immediate and audited
at the normal severity.

## Security

- Tenant from the authenticated context; the finding must be in the caller's data scope
  (404 otherwise, never 403), the same check as `/transitions`.
- Reads only: the retest availability check records nothing (tested).
- Exposes the user id that completed the checklist, which members of the tenant already
  see on the checklist itself.
- Closing mode: the policy is read from the caller's own organization (token
  singleton route); the tier query is tenant-scoped, and an id it does not return is kept
  open. Tests: `pkg/domain/vulnerability/closure_decision_test.go` (every cell),
  `internal/app/ingest/closure_mode_test.go` (review, auto, off, dry_run ceiling, held run,
  unknown id), `tests/unit/closure_settings_service_test.go` (step-up, owner-only, audit
  severity), `internal/infra/postgres/finding_closure_tiers_db_test.go` (cross-tenant).
- Tests: `internal/app/finding/verification_plan_test.go` (per source, type, asset,
  availability and tier), `internal/app/retest` `TestRetestDB_AvailabilityReasons`,
  `internal/infra/http/routes/finding_verification_plan_db_test.go` (secret plan,
  completer told another person resolves, out of scope and cross-tenant 404).
