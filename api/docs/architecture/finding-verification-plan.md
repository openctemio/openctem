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

**Loosening waits 24 hours.** A change that lets the platform close more alone (off to
review or auto, review to auto, `critical_auto_close` on) needs a recent
re-authentication, is audited high, tells every owner and administrator, and takes
effect `tenant.ClosureRelaxationDelay` (24 h) later: the stored policy is the stricter of
the old and the new one, field by field, and the new one waits in `pending_mode`,
`pending_critical_auto_close`, `pending_at` (written only by the platform; a request's
values are ignored). Readers (the evaluator, the verification plan, `GET`) use the
policy in force at the time of the read (`ClosureSettings.EffectiveAt`), so no job flips
it. Any tightening choice applies at once and drops the waiting change;
`DELETE /api/v1/organization/settings/closure/pending` (owner or administrator, audited)
cancels it. The settings live on Settings > Finding lifecycle, section Closing findings.

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
(alias `tenant`) applies the closing mode to coverage auto-resolve of non-repository
findings. The ceiling does not govern the other automatic closes below, which always
apply the organization's mode.

**Every automatic close goes through the rule** (shared implementation in
`internal/app/closuremode`): the writer reads the organization's policy once per run, the
tiers of the findings in one tenant-scoped query (`FindingRiskTiers`), closes only
`close`, and records `propose` as Ready to close proposals. `off` keeps every finding
open and records nothing; `review` proposes every close; `auto` closes per the tier rule.

| Automatic close | Method | Where |
|---|---|---|
| coverage auto-resolve of a covered scan | `covered_scan` | `ingest/closure_mode.go`, `coverage_autoresolve.go` (receipt `coverage.note = review`, audit `decision = review`) |
| a clean full default-branch scan (repository findings) | `ci_default_branch` | `evaluateRepoCoverage` |
| a full-coverage upload (`coverage=full`) | `covered_scan` | `findingimport/coverage.go` (receipt `coverage.note = proposed` when it only proposed) |
| the software matcher sees another installed version (`version_changed`) | `source_reported` | `vulnmatch/service.go` |

The matcher's other kinds are not fix claims and stay outside the rule: `not_observed`
only marks a finding stale, and `advisory_updated` reclassifies a finding as a detection
error (false positive). The verification plan names the organization's mode: `coverage_critical_review`
(critical waits in auto), `coverage_org_review`, `coverage_org_off`; the
`coverage_auto_resolve_*` reasons stay for the platform ceiling. A held run (blinding
guard), template drift and secrets behave as before: a held run never closes, and (except
under `off`) its findings are proposed for a person to decide. When the policy or the
tiers cannot be read, nothing closes (review; tiers read as critical). The verification
plan's `covered_scan` method uses the same rule. Confirming a `ci_default_branch` proposal
records verification `covered_scan`; a `source_reported` one records `source_reported`.

## Ready to close

A `propose` decision is stored in `finding_closure_proposals` (tenant-scoped, one
`pending` row per finding by a partial unique index, row security policy like
`findings`). The writers above record it: for each finding the closing mode or the tier
rule proposes, and for every candidate of a run the blinding guard holds (a held run
closes nothing; a person decides). Coverage auto-resolve records proposals in `enforce`
only. A second qualified look
refreshes the pending row's `evidence` and `evidence_at`. The evidence is the look:
command, tool, profile, template release digest, reporting sensors, whether the run was
held, bounded to 4 KiB. A proposal is never a status: the finding stays open.

| Endpoint | Gate | Does |
|---|---|---|
| `GET /api/v1/findings/closure/proposals` | `findings:read` | pending, eligible proposals in the caller's data scope, critical first then oldest |
| `POST /api/v1/findings/closure/proposals/decide` | `findings:verify`; every confirm (single or bulk) needs a recent re-authentication, dismissal does not | `confirm` closes each finding as `fixed`, verification = the proposal's method, `resolved_by` = the person, one transaction with the proposal row and the timeline entry; `dismiss` keeps it open with a reason (`still_present_manual_check`, `scan_not_trustworthy`, `wrong_asset`, `other` + note). At most 200 ids |
| `GET /api/v1/findings/closure/auto-closed` | `findings:read` | findings the platform closed by itself in the last 7 days and still closed, with the evidence of the close |
| `POST /api/v1/findings/{id}/reopen` | `findings:status` | reopens such a finding as `confirmed`: the close was wrong. Not counted as a regression |

**Eligibility** is re-checked inside the confirm statement: the finding is still in a
status a platform close starts from, not a secret or a protected source, and not seen
after `evidence_at`. Anything else is skipped as `not_eligible`; a proposal outside the
caller's scope, another tenant's or no longer pending is `not_found`. Each evaluation in
`enforce` also cancels the tenant's pending proposals whose finding was seen again
(`seen_again`) or left the open statuses (`status_changed`).

**Counts** ride the bootstrap: `badges.ready_to_close` (only with `findings:verify` and
the findings module, counted in the caller's data scope), so no page sends a request
for it. Decisions are audited (`finding.closure_confirmed` high,
`finding.closure_dismissed`, `finding.auto_close_reopened`).

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
- Ready to close: reads and decisions take the caller's data scope (asset scope or the
  finding's assignee, `filterspec.AssigneeScopeSQL`) and the tenant in every predicate.
  Threats: a stolen session confirming a queue (step-up above one confirm, bulk cap
  200), a stale proposal closing a finding that came back (eligibility re-check, sweep),
  a sensor blinding a run (held runs only propose). Tests:
  `internal/infra/postgres/finding_closure_proposal_repository_db_test.go` (one pending
  row, cross-tenant and out-of-scope list, confirm, reopen; seen again; dismiss),
  `internal/app/ingest/closure_proposals_test.go` (auto, held run, dry run),
  `internal/infra/http/routes/step_up_routes_test.go` `TestClosureDecisionStepUp_EveryConfirm`.
- Tests: `internal/app/finding/verification_plan_test.go` (per source, type, asset,
  availability and tier), `internal/app/retest` `TestRetestDB_AvailabilityReasons`,
  `internal/infra/http/routes/finding_verification_plan_db_test.go` (secret plan,
  completer told another person resolves, out of scope and cross-tenant 404).
