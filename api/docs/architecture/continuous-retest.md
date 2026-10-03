# Continuous retest (RFC-039)

> How OpenCTEM re-checks findings so their status stays true: a fixed issue is
> closed and a regression reopened without a person. Design and decisions:
> [RFC-039](../rfcs/RFC-039-continuous-retest.md). Related:
> [validation engine](validation-engine.md) (the `validate` command transport a
> retest reuses).

## What a retest is

A retest re-runs **the exact check that produced a finding** — in Phase 1 the
nuclei template (`findings.rule_id`) against the finding's own target — plus a
**reachability probe** of the same target, and settles the finding:

| Template re-run | Target reachable? | Outcome | Finding |
|---|---|---|---|
| matched | any | `still_present` | open: unchanged · `resolved` → `confirmed` (regression) · `fix_applied` → `in_progress` · `validated_fixed` → `confirmed` |
| no match | yes | `fixed` | → `resolved`, `resolution_method = retest_verified` (`resolved` stays) |
| no match | no / unknown | `unknown` | unchanged ("target unreachable") |
| inconclusive / error / no result / deadline passed | any | `unknown` | unchanged |

The probe exists because nuclei prints nothing and exits 0 when a host does not
answer, which the sensor reports as `not_detected`: without it a down host, a
firewall change or a sensor in the wrong zone would read as "fixed".

Eligible findings: `tool_name = nuclei` with a template id that passes the
template guard (no path, no `dos`/`fuzz`/`intrusive`/`brute-force` marker), in
`new`, `confirmed`, `in_progress`, `fix_applied`, `validated_fixed` or
`resolved`, on an `active`, network-addressable asset that passes the scope
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

## Code

| Piece | Where |
|---|---|
| Outcome and transition rules (pure) | `pkg/domain/retest/retest.go` (`Decide`, `NextStatus`) |
| Service: request, gates, limits, dispatch, settle, sweep | `internal/app/retest/service.go`, `gates.go` |
| Auto-retest tick (claim once) | `internal/app/retest/auto.go` |
| Persistence + settle transaction + cursors | `internal/infra/postgres/finding_retest_repository.go`, migration `000281_finding_retests` |
| Completion hooks | `internal/infra/http/handler/command_handler.go` (`triggerValidationEvidence`, `triggerRetestSettle`) |
| Routes / handler | `internal/infra/http/routes/finding_retest.go`, `internal/infra/http/handler/finding_retest_handler.go` |
| Controller | `internal/infra/controller/retest_scheduler.go` |
| Tenant setting | `pkg/domain/tenant/retest_settings.go` |
| Web: Retest now + last retest | `web/src/features/findings/components/detail/finding-retest.tsx` |

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
