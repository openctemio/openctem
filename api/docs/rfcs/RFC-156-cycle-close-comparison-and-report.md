# RFC-156: Cycle close, comparison and report

| | |
|---|---|
| Status | Accepted (2026-11-12): design only, nothing built. Open questions in §14 |
| Scope | api (CTEM cycle metrics, a cycle metrics controller, cycle routes, report schedule types, a cycle report renderer), web (cycle detail, cycles list, reports) |
| Architecture | [program-metrics.md](../architecture/program-metrics.md), [validation-engine.md](../architecture/validation-engine.md), [dashboards.md](../architecture/dashboards.md) |
| Related | RFC-155 (validation recorded by a person), RFC-011.2 (confirm-or-downgrade loop), RFC-111 (approval policy) |

## 1. Problem

A CTEM cycle ends with two deliverables: figures that say what the cycle
changed, and a report a sponsor reads. Today the figures of a closed cycle are
not truly fixed, two cycles cannot be set side by side, and there is no cycle
report. The figures the Validation stage asks for (how much validation lowered
priority, how fast a validated finding became a ticket) and the Scoping
feedback figure (new P0 and P1 findings on the previous cycle's assets) are not
measured at all.

## 2. Today (checked on develop, 2026-11-12)

Paths are relative to `api/`.

- **Close.** `POST /api/v1/ctem-cycles/{id}/close` (`ctem:cycles:write`)
  moves a cycle from review to closed, then computes and stores its metrics
  best-effort (`internal/infra/http/handler/ctem_cycle_handler.go:477-586`,
  `persistMetrics` in `ctem_cycle_metrics_handler.go:190-236`). A failure is
  logged and the close still succeeds.
- **Not frozen.** `GET /api/v1/ctem-cycles/{id}/metrics` recomputes a closed
  cycle when it has no rows or its success criteria were never evaluated
  (`ctem_cycle_metrics_handler.go:79-90`). `UpsertBatch` deletes every row of
  the cycle and inserts new ones (`internal/infra/postgres/ctem_cycle_metrics_repository.go:330-375`).
  `Compute` reads the window `[activated_at, closed_at]` but today's finding
  state (for example `priority_class` for `p0_resolved`), so a late compute
  gives figures the cycle never had.
- **No tenant column.** `ctem_cycle_metrics` (id, cycle_id, metric_type,
  value numeric(12,2), computed_at) and `ctem_cycle_scope_snapshots` (id,
  cycle_id, asset_id, scope_target_id, included_at) have no `tenant_id`
  (`migrations/001146_baseline.up.sql:4271-4290`); tenant checks join
  `ctem_cycles`.
- **Metric types.** `mttr_hours`, `findings_opened`, `findings_resolved`,
  `p_class_churn`, `validation_coverage`, `scope_drift_size`
  (`pkg/domain/ctemcycle/review.go:90-95`), `p0_resolved`, `p1_resolved`,
  `risk_before`, `risk_after`, `risk_reduction_pct`,
  `charter_completion_rate` (`pkg/domain/ctemcycle/criteria.go:51-57`).
- **Across cycles.** `GET /api/v1/ctem-cycles/metrics/trend` returns each
  metric's series over the closed cycles and the maturity breakdown, from
  stored rows (`ctem_cycle_metrics_handler.go:123-185`). There is no read of
  chosen cycles side by side.
- **Organization figures.** Cycle metrics cover the whole organization: a
  restricted member needs `dashboards:org:view` or full data access
  (`allowOrgMetrics`, `ctem_cycle_metrics_handler.go:264-293`); the charter
  evaluation is left out of a cycle for anyone else (`withVisibleEvaluation`).
- **Lessons.** `POST /api/v1/ctem-cycles/{id}/scope-refinement` stores
  `scope_refinement_notes` in the charter JSONB, allowed in review and closed
  (`ctem_cycle_handler.go:588-625`, `pkg/domain/ctemcycle/entity.go:57-60`).
- **Several active cycles.** Nothing enforces one active cycle per tenant
  (`idx_ctem_cycles_tenant` is not unique).
- **Reports.** Schedule types are listed twice: `validReportTypes`
  (`pkg/domain/reportschedule/entity.go:19-23`: `executive_summary`,
  `summary`, `findings`) and `supportsType`
  (`internal/infra/controller/report_scheduler.go:309-316`). Recipients must
  be active members or in the organization's allowed e-mail domains
  (`RecipientPolicy`, `entity.go:340-375`). The executive summary is server
  HTML through `html/template`, printed to PDF by the browser
  (`internal/infra/http/handler/executive_summary_html.go`,
  `GET /api/v1/dashboard/executive-summary/export`, `dashboard:read`).
  Pentest reports have a pure-Go PDF renderer
  ([report-pdf-export.md](../architecture/report-pdf-export.md)).
- **Program Health.** `GET /api/v1/dashboard/program-metrics` computes its
  figures on read (`internal/infra/http/routes/misc.go:171`,
  `internal/infra/postgres/dashboard_program_metrics.go`).

## 3. Decisions

**C1. Figures freeze at close.** A cycle's metric rows are written by one
path, the cycle metrics service. While a cycle is active or in review, a
controller refreshes its rows hourly. Close runs one final compute in the
same request and sets `ctem_cycles.metrics_frozen_at`. After that, no code
path deletes, updates or inserts metric rows of that cycle; the repository
refuses with `ErrMetricsFrozen` (a test asserts it on every write method).

**C2. Late fill, once.** A closed cycle with no rows (closed before this
change, or the final compute failed) is filled once, by the controller or on
read, and then frozen. Its rows carry `computed_late = true` and the report
and the API say "computed after close on <date>". A closed cycle with rows
but no `metrics_frozen_at` (closed before this change) is frozen as it is,
without recompute, by the backfill migration.

**C3. Close does not fail on figures.** If the final compute fails, the cycle
still closes, `metrics_frozen_at` stays NULL and C2 fills it later. The close
response says the figures are pending.

**C4. New figures** (all stored per cycle, over the window `[activated_at,
closed_at]`, null when there is no sample, never 0):

| metric_type | Definition |
|---|---|
| `validated_count` | Findings with at least one validation result (machine or person, RFC-155) inside the window |
| `validation_downgrade_pct` | (findings with an RFC-155 lowering **applied** inside the window) / (findings validated inside the window while P0 to P2) x 100 |
| `validation_not_reproducible_pct` | The RFC-011.2 meaning: findings downgraded (`downgraded_at`) inside the window / findings validated inside the window x 100 |
| `validation_to_ticket_median_hours` | Median over findings whose first `exploitable=yes` record or reproducible verdict falls inside the window: hours from it to the finding's first remediation task (`remediation_tasks`) or external ticket link (`finding_issue_links`). A finding with no ticket by window end is counted in a separate `validation_to_ticket_open` count, not in the median |
| `new_p1_in_prior_scope` | Findings that first reached P0 or P1 inside the window, on assets in the previous closed cycle's scope snapshot (the cycle with the latest `closed_at` before this one's `activated_at`). Null when there is no previous cycle |
| `owner_coverage_pct` | Share of this cycle's scope snapshot assets with a primary owner at compute time |

Both validation meanings are shown, labelled, never summed.

**C5. Comparison reads frozen rows only.** A cycle comparison takes 2 to 4
closed, frozen cycles of the caller's tenant and returns their stored rows
and charter evaluations side by side, with each figure's definition. It never
computes.

**C6. The cycle report.** One server-rendered HTML report per cycle, built
only from stored rows, the charter, the charter evaluation and the scope
refinement notes. An open cycle renders as a draft with "figures as of
<computed_at>". The browser prints it to PDF (as the executive summary).

**C7. Report sharing.** The report is organization-wide: viewing, exporting
or scheduling it needs `ctem:cycles:read`, `reports:read` and organization
visibility (full data access or `dashboards:org:view`, the `allowOrgMetrics`
rule). Scheduled delivery uses the existing recipient policy (active members
or allowed e-mail domains). There are no public or tokenized links.

**C8. Names stay out by default.** The report carries figures, not finding
titles or asset names. The option "include the top 10 open P0 and P1
findings" is off by default, lists only findings in the generating user's
data scope, is recorded in the audit, and is not available on a schedule (a
schedule has no viewer whose scope could filter it).

**C9. Next-scope recommendation.** The existing `scope_refinement_notes`
is the recommendation; it is not duplicated. It is capped at 4 KiB in the
domain and shown in the report under "Next scope".

## 4. Data model

Expand migration (`make -C api migration-new name=cycle_metrics_tenant`):

- `ctem_cycle_metrics.tenant_id uuid` and `ctem_cycle_scope_snapshots.tenant_id
  uuid`, nullable; backfilled from `ctem_cycles` in batches of 5000 in the
  migration's own loop (both tables are small: tens of rows per cycle for
  metrics, scope size for snapshots); composite FK `(tenant_id, cycle_id)` to
  `ctem_cycles (tenant_id, id)` added `NOT VALID` then validated. A unique
  index `(tenant_id, id)` on `ctem_cycles` is built `CONCURRENTLY` first, in
  its own migration, where RFC-155 has not added it already.
- `ctem_cycle_metrics.computed_late boolean NOT NULL DEFAULT false`.
- `ctem_cycles.metrics_frozen_at timestamptz`; the backfill sets it to
  `closed_at` for closed cycles that already have rows (C2).
- A trigger on `ctem_cycle_metrics` refuses INSERT, UPDATE and DELETE when the
  cycle's `metrics_frozen_at` is set, unless the session sets
  `openctem.metrics_late_fill = on` (used only by the C2 fill, inside the same
  transaction that sets `metrics_frozen_at`). Defence in depth behind C1.
- The writers set `tenant_id` from this release on.

Contract migration in the next PR, no release wait: `tenant_id SET NOT NULL`
on both tables (after the backfill check shows no NULL).

New `metric_type` values (C4) need no schema change.

## 5. Controller

`ctem-cycle-metrics`: leased, hourly. For each active or review cycle it
computes and replaces the rows (the cycle is not frozen yet). For each closed
cycle with no `metrics_frozen_at`, it runs the C2 fill once. Batches of 50
cycles per run, oldest `computed_at` first. Close calls the same service
synchronously for its final compute.

## 6. API

Contract regenerated; route coverage and data-scope registries updated (the
three reads are classified as organization-wide figures, like
`/metrics`).

| Verb | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/v1/ctem-cycles/compare?ids=a,b,c` | `ctem:cycles:read` + organization visibility | 2 to 4 distinct ids. Any id that is foreign, unknown, open or not frozen gives 404 for the whole request (no partial answer, no hint which). Registered before `/{id}` |
| GET | `/api/v1/ctem-cycles/{id}/report` | `ctem:cycles:read` + `reports:read` + organization visibility | `text/html`, `Content-Disposition: attachment`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox`, `X-Content-Type-Options: nosniff`. Query `top=10` only with C8's rules |
| GET | `/api/v1/ctem-cycles/{id}/metrics` | unchanged | Now never recomputes a frozen cycle; adds `metrics_frozen_at` and `computed_late` |
| POST | `/api/v1/reports/schedules` | unchanged (`reports:write`) | New type `cycle_report`: "the latest closed cycle". The creator must have organization visibility at creation; the scheduler re-checks the creator's visibility at each run and skips with a logged reason when it is gone |

Report types move to one registry map (type, renderer, visibility rule)
read by both the schedule validation and the scheduler, replacing
`validReportTypes` and `supportsType`.

## 7. Permissions and step-up

No new permission. Reading frozen figures carries no step-up. Exporting is a
read and is audited. The `top=10` option exposes names already in the
viewer's scope; no step-up.

## 8. Tenant isolation

- Every query names `tenant_id`; the new composite FKs stop a metric or
  snapshot row from pointing at another tenant's cycle (a test inserts one
  and expects a refusal).
- Compare loads all ids with one tenant-scoped query and answers 404 unless
  every id came back.
- The controller reads across tenants only to find due cycles; each write
  names the cycle's tenant.
- `new_p1_in_prior_scope` joins the previous cycle by tenant and the
  snapshot by `(tenant_id, cycle_id)`.

## 9. Audit

| Action | Severity |
|---|---|
| `ctem_cycle.metrics_frozen` | low |
| `ctem_cycle.metrics_late_filled` | medium |
| `ctem_cycle.report_exported` (with `top` used or not) | medium |
| `ctem_cycle.report_sent` (schedule id, recipient count) | medium |

## 10. UI surfaces

Boards (redesign canvas): **P1-CycleDetail-Report** (the close result and
"Export report" on the cycle detail), **P1-Cycles-Compare** (choose 2 to 4
closed cycles on the cycles list, figures side by side with definitions),
**P2-Reports-CycleReport** (the report type on the Reports page, preview and
schedule).

Simplest path: on a closed cycle, one action "Export report". On the cycles
list, select closed cycles and "Compare". The top-10 option is folded under
"More options" with a note that it adds names. Until the redesign, the live
console gets only "Export report" on the cycle detail and the new figures in
existing Program Health rows (plan item 1.10); compare and the Reports page
type wait for their boards. All text through i18n, en and vi.

## 11. Threat cases

| Threat | Closed by | Test |
|---|---|---|
| A restricted member reads organization-wide figures | Organization visibility on compare, report and metrics | 403 for a scoped member without `dashboards:org:view` |
| Rewriting a closed cycle's history | C1 repository refusal plus the freeze trigger | Every write after freeze refused; a late read never recomputes |
| Stored XSS from charter text, criteria or notes | `html/template` escaping, CSP with `sandbox`, attachment download | A script in every charter field renders inert |
| Cross-tenant compare ids | One tenant-scoped load, all-or-404 | Mixed own and foreign ids give 404 |
| Report sent outside the organization | Existing recipient policy, creator visibility re-checked per run | Run after the creator lost visibility sends nothing |
| Names leak through the report | Off by default, viewer's scope, audited, not on schedules | Scoped viewer sees only in-scope titles |
| Metric gaming through validation | Only applied lowerings count (RFC-155 R12) | Pending and rejected excluded |
| Heavy recompute load | Hourly, batches of 50, frozen cycles never recomputed | Controller run on 1k cycles stays within its lease |

## 12. Rollout (expand, then contract)

1. Expand migration, freeze trigger, writers set `tenant_id`, the controller,
   close and lazy paths changed (plan 1.5).
2. Contract migration: `tenant_id NOT NULL` (plan 1.5c).
3. Compare read (plan 1.7).
4. New figures, after RFC-155's effect lands (plan 1.6).
5. Report registry, `cycle_report` renderer, route and schedule type (plan
   1.8).
6. Live "Export report" and Program Health figures (plan 1.10).

## 13. Out of scope

- Server-side PDF of the cycle report (the pure-Go renderer could follow).
- An AI-written narrative.
- Comparing open cycles.
- Moving the existing Program Health figures to snapshots.
- An "until the end of this cycle" acceptance preset (plan item 2.7).
- Enforcing one active cycle per tenant.

## 14. Open questions for the owner

1. **Downgrade share in the headline.** C4 reports the person-proven
   lowering share and the not-reproducible share side by side. Which one is
   the headline figure on the report and Program Health?
2. **Recipients outside members.** C7 keeps the existing policy, which also
   allows the organization's allowed e-mail domains. Should a cycle report be
   members only?
3. **Server PDF.** Is a server-rendered PDF needed for sponsors before the
   redesign, or is browser print enough?
4. **Ticket definition.** `validation_to_ticket` counts a remediation task or
   an external ticket link. Should only an external ticket count?
</content>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /home/ubuntu/projects/openctemio/agent-ops/work/ctem-rfcs/repo/api; grep -n "remediation_task\|ticket" internal/infra/postgres/ctem_cycle_metrics_repository.go | head -3; grep -n "downgraded_at" migrations/001146_baseline.up.sql | head -2; grep -rln "primary_owner\|ownership_type = 'primary'\|'primary'" internal/infra/postgres/*owner*.go | head -2