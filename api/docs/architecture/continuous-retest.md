# Continuous retest (RFC-039)

> How OpenCTEM re-checks findings so their status stays true: a fixed issue is
> closed and a regression reopened without a person. Design and decisions:
> [RFC-039](../rfcs/RFC-039-continuous-retest.md). Related:
> [validation engine](validation-engine.md) (the `validate` command transport a
> retest reuses).

## What a retest is

A retest re-runs **the exact check that produced a finding** — in Phase 1 the
nuclei template (`findings.rule_id`) against the finding's own target (the
origin of its matched-at URL, see below) — plus a
**reachability probe** of the same target, and settles the finding:

| Template re-run | Target reachable? | Outcome | Finding |
|---|---|---|---|
| matched | any | `still_present` | open: unchanged · `resolved` → `confirmed` (regression) · `fix_applied` → `in_progress` · `validated_fixed` / `not_observed` → `confirmed` |
| no match | yes | `fixed` | → `resolved`, `resolution_method = retest_verified` (`resolved` stays) |
| no match | no / unknown | `unknown` | unchanged ("target unreachable") |
| inconclusive / error / no result / deadline passed | any | `unknown` | unchanged |

The probe exists because nuclei prints nothing and exits 0 when a host does not
answer, which the sensor reports as `not_detected`: without it a down host, a
firewall change or a sensor in the wrong zone would read as "fixed".

Eligible findings: `tool_name = nuclei` with a template id that passes the
template guard (no path, no `dos`/`fuzz`/`intrusive`/`brute-force` marker), in
`new`, `confirmed`, `in_progress`, `fix_applied`, `validated_fixed`,
`not_observed` or `resolved`, on an `active`, network-addressable asset that passes the scope
gates. `false_positive`, `accepted`, `duplicate`, suppressed and pentest
findings are never retested.

## Flow

```
POST /api/v1/findings/{id}/retests            (findings:verify + data scope)
  └─ retest.Service.Request
       ├─ eligibility, scope gates (fail closed), limits, validate:nuclei sensor online
       ├─ INSERT finding_retests (pending)      ← one pending per finding (unique index)
       ├─ validate command: executor nuclei, template_id, retest_id   ┐ same queue, poll,
       ├─ validate command: executor safe-check, retest_id            ┘ lease, expiry as scans
       └─ activity retest_requested + audit finding.retest_requested

sensor completes / fails a command
  └─ CommandHandler.triggerValidationEvidence / Fail
       ├─ retest_id set → IngestAdvisory (evidence visible, NOT applied)
       └─ retest.Service.OnCommandFinished → both checks terminal?
            └─ FindingRetestRepository.Settle (one transaction):
                 lock retest (pending?) → lock finding, read status → NextStatus
                 → move finding → complete retest → activity retest_completed
                   (actor_type system, actor_name "system: retest")

RetestScheduler (controller, every minute, every replica)
  ├─ Sweep: settle retests whose checks ended or whose 30-min deadline passed
  └─ RunAutoTick: tenants with settings.retest.auto_enabled
       ├─ ClaimTenantTick: compare-and-set on finding_retest_cursors.next_run_at
       └─ winner queues min(daily budget left, in-flight room, per-pass cap)
          oldest-retested eligible findings, through the same Request path
```

## Target: the origin, never the matched-at URL

The re-run's input is the origin (`scheme://host[:port]`) of the finding's
matched-at URL when its host is the asset's host, else the asset name
(`retest.ResolveTarget`). A template appends its own path to the input
(`{{BaseURL}}/wp-admin/js/theme.js`); with the matched-at URL as the input the
re-run requested `/wp-admin/js/theme.js/wp-admin/js/theme.js`, got a 404 and
reported "did not match", which settled as `fixed`. Migration 001175 voided
those outcomes: each finding a path-target retest resolved, and that nothing
changed since, returns to its prior status and the retest reads `unknown`
with a `voided:` reason.

## Template digest drift (research/18 O6)

A retest proves something only when it re-ran the template content the
finding was last seen with. The sensor (sensor#134) reports, per nuclei
finding, `properties.template_digest` (sha256 of the matching template file)
and `template_path`, and per report the template release in
`tool.properties.content` (`nuclei-templates`: version, archive digest).
Ingest keeps them on the finding as the last sighting's baseline (migration
001015: `findings.template_digest`, `template_path`, `templates_version`,
`templates_digest`, `template_seen_at`; sanitized: sha256 digests only, a
relative path without `..`, a short version token). A sighting without a
digest keeps the baseline; one with a new digest re-baselines.

When the retest settles (`retestdom.ApplyTemplateDrift`), a conclusive
outcome (`fixed` or `still_present`) becomes `unknown` (inconclusive, the
finding does not move) when the finding has a baseline digest and the
template re-run reported a different digest or none
(`evidence.template_digest`). A finding without a baseline (sighted before
provenance existed, or by another tool) is decided as before. A baseline that
cannot be read is inconclusive (fail closed).

The scan side is coverage auto-resolve: a covered nuclei run whose template
release differs from the release of a candidate's last sighting (or that
reported none) does not resolve that candidate; in enforce mode it becomes
`not_observed` ([finding-status-not-observed.md](finding-status-not-observed.md)).
A run whose reports disagree on the release counts as reporting none.

## Limits (server-side)

| | |
|---|---|
| pending retests per finding | 1 |
| cooldown per finding | 10 min |
| in flight per asset | 3 |
| in flight per tenant | 20 manual, 50 auto |
| auto daily cap per tenant | `settings.retest.daily_cap`, default 200, max 2000 |
| auto interval | `settings.retest.interval_hours`, default 24, 6–168 |
| auto queued per scheduler pass, all tenants | 100 |
| retest deadline | 30 min |
| resolved findings re-checked by auto | resolved in the last 90 days |

## Settings and API

| Route | Gate |
|---|---|
| `POST /api/v1/findings/{id}/retests` — Retest now (202) | `findings:verify` + data scope |
| `GET /api/v1/findings/{id}/retests` — history, newest first | `findings:read` + data scope |
| `GET/PUT /api/v1/organization/settings/retest` — `auto_enabled`, `interval_hours`, `daily_cap` (audited `tenant.retest_updated`) | team admin |

Auto-retest is **off** for every tenant until an admin turns it on (owner
ordering: until the scans redesign P1 lands).

## Regression reopen from scans

Independently of retests, ingest reopens every re-detected finding that was
closed as fixed — by a scan or by a person — and (since RFC-039) every
`validated_fixed` one: `AutoReopenByFingerprintsBatch` locks the rows, reopens
them to `confirmed` and returns what it cleared. The `auto_reopened` activity
keeps `previous_status`, `previous_resolution`, `previous_resolution_method`,
`previous_resolved_by`, `previous_resolved_at`, `scanner` and `scan_id`, so the
person who resolved it is never lost. Deliberate dispositions are never
reopened.

## Phase 2: what follows a status change (owner decisions D2–D4)

- **Fresh SLA on a regression (D2).** A finding closed as fixed that a scan or
  a retest sees again gets a new SLA deadline computed by the tenant's policy
  (priority class, then severity) from the reopen, `sla_status = on_track`, and
  an `sla_restarted` activity with the reason, the trigger (`scan`/`retest`) and
  the previous deadline (`sla.RegressionRestarter`,
  `postgres.FindingSLARestartRepository`). A `validated_fixed` finding a scan
  reopens was never closed: its SLA keeps running.
- **Announcements.** A retest that resolves a finding (`finding_fixed`), a
  regression (`finding_reopened`) and a rejected fix (`fix_applied` still
  detected, `finding_reopened`) queue a notification and comment on the linked
  Jira issue — only when the tenant enabled outbound sync on its Jira
  integration (`jira.SyncService.CommentOnFinding`). Platform-written text only,
  free text capped at 300 characters, at most 50 announcements per scan
  (`retest.ChangeAnnouncer`, `retest.ScanRegressions`).
- **Honest `/validate` (D3).** See [validation-engine.md](validation-engine.md):
  a safe-check never moves a finding; a nuclei miss without proof the target
  answered is unknown.
- **Proof of fix (D4).** Marking a finding `fix_applied` (or a Jira "Done")
  starts a `proof_of_fix` retest for a nuclei finding (`retest.ProofOfFix`),
  else the validation re-check. The whole-asset "Request verification scan"
  (`POST /findings/{id}/request-verification`) is removed, with its service,
  adapter and web button.

## Code

| Piece | Where |
|---|---|
| Outcome and transition rules (pure) | `pkg/domain/retest/retest.go` (`Decide`, `NextStatus`) |
| Service: request, gate preflight, limits, dispatch, settle, sweep | `internal/app/retest/service.go`; the gate: [active-probe-gate.md](active-probe-gate.md) |
| Auto-retest tick (claim once) | `internal/app/retest/auto.go` |
| Persistence + settle transaction + cursors | `internal/infra/postgres/finding_retest_repository.go`, migration `000281_finding_retests` |
| Completion hooks | `internal/infra/http/handler/command_handler.go` (`triggerValidationEvidence`, `triggerRetestSettle`) |
| Routes / handler | `internal/infra/http/routes/finding_retest.go`, `internal/infra/http/handler/finding_retest_handler.go` |
| Controller | `internal/infra/controller/retest_scheduler.go` |
| Tenant setting | `pkg/domain/tenant/retest_settings.go` |
| Web: Retest now + last retest | `web/src/features/findings/components/detail/finding-retest.tsx` |
| Fresh SLA on regression | `internal/app/sla/regression.go`, `internal/infra/postgres/finding_sla_restart_repository.go`, migration `000285_retest_phase2` |
| Announcements, scan regressions, proof of fix | `internal/app/retest/announce.go`, `internal/app/retest/proof_of_fix.go`, `internal/app/jira/sync_service.go` (`CommentOnFinding`) |

## Tests

- `pkg/domain/retest/retest_test.go` — outcome and transition tables.
- `internal/app/retest/service_db_test.go` — end to end against Postgres:
  fixed, unreachable → unknown, regression reopen, one in flight + cooldown,
  deadline sweep, ineligible findings, two scheduler replicas never double-fire,
  auto off by default.
- `internal/infra/http/routes/finding_retest_authz_db_test.go` —
  `findings:verify`, cross-tenant 404, data scope 404.
- `internal/infra/postgres/finding_reopen_regression_db_test.go` — a scan
  regression keeps the previous resolver; `validated_fixed` reopens.

## Tool retest

A finding whose tool has a retest handler on a tenant sensor (capability
`retest:<tool>`, sdk-go tool contract) is retested by **one `retest` command**
to that tool instead of the two `validate` commands. The tool answers a verdict
per finding: `still_present`, `fixed` or `unverifiable`. The retest service
settles from the verdict for its own finding: still present, fixed, or unknown
for anything else. The nuclei validate pair remains the fallback for nuclei
findings when no sensor offers `retest:nuclei`. The payload names the tool as
`scanner` and lists plain addresses, so it passes the same claim-time tool
predicate, active-probe gate, zone pinning and sensor-side local policy as a
scan. Design and threat model: [RFC-039 §12](../rfcs/RFC-039-continuous-retest.md).
