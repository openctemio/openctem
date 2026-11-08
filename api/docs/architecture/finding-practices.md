# Finding practices

Design: [RFC-152](../rfcs/RFC-152-finding-practices.md).

A finding's **practice** is the program that triages it. Three fields answer
three questions and stay separate:

| Field | Answers | Example |
|---|---|---|
| `finding_type` | what kind of problem | vulnerability, secret, misconfiguration, compliance, license |
| `source` | which technique detected it | sast, sca, va, dast, easm |
| `practice` | which program triages it | aspm, infra, external, compliance |

The nine practices: `aspm` (application security: code, dependencies, images,
pipelines, application tests), `infra` (network and host vulnerability
assessment), `external` (attack surface), `cloud` (cloud posture),
`compliance` (benchmark check results), `offensive` (pentest, red team, bug
bounty), `identity` (identity assets), `runtime` (runtime detections),
`other` (no signal).

## How it is set (shipped)

- `findings.practice` (`varchar(16)`, default `other`, CHECK on the nine
  values) and `findings.practice_reason` (the code of the rule, NULL for a row
  never derived). Index `(tenant_id, practice, status)`.
- `vulnerability.DerivePractice` (`api/pkg/domain/vulnerability/practice.go`)
  holds the ordered rules (RFC-152 §3). Every insert path of the finding
  repository (`Create`, `CreateInTx`, `CreateBatch`, `CreateBatchWithResult`)
  derives the practice right before the insert, reading the facts of the
  findings' assets with one query per tenant, pinned to the tenant
  (`internal/infra/postgres/finding_practice_columns.go`).
- Ingest sends no extra statement for it: the asset processor already holds
  every asset the report's findings land on, after its own upsert, and
  records their facts (stored type, internet-facing) for the batch tenant;
  the findings processor attaches them to the new findings
  (`internal/app/ingest/practice_facts.go`). A finding without attached facts
  (an asset that lost a concurrent create, another path) is read as above.
- A re-sighting (the upsert) keeps the stored practice, except for a row never
  derived and a row whose type changed; a closed finding keeps its practice.
  `SetFindingType(compliance)` moves the entity to compliance at once (that
  rule reads no asset fact). `Update` writes the entity's practice back.
- Compliance means `finding_type = compliance` and nothing else.

## Where it is used (shipped)

- Findings registry fields (`api/pkg/domain/vulnerability/finding_fields.go`):
  `practice` (enum, in / not in, sortable) and `compliance_result` (pass, fail,
  manual for a scanner WARNING, not_applicable, error, unknown; NULL on
  non-compliance findings, so `compliance_result_not=pass` keeps them). Every
  list, stats, groups and export read and every saved view take them, with
  the caller's data scope.
- Query language: `findings where practice != compliance | count by practice`;
  both fields can be grouped.
- MCP `list_findings`: `practice`, `exclude_practice`, `compliance_result`.
- The finding response and the export carry `practice` (the reason code is in
  the response only).

## The findings list's practice switch (shipped)

- A tab strip above the list: **Vulnerabilities** (the default: every
  practice except compliance, `practice_not=compliance`), **Compliance**, each
  other practice that holds findings, and **All**, each with the caller's
  count. One click shows compliance.
- The choice is the page's `practice` URL param (absent = Vulnerabilities,
  `all` = no condition, else the practice), so it is linkable and a saved view
  keeps it (`all` is saved as no condition). Like the state lens, the default
  is not laid on top of an open saved view; a practice picked explicitly is.
- Counts: `GET /api/v1/findings/practice-counts` takes every filter param of
  `GET /findings` (and `view`), leaves any practice condition out, and returns
  `total`, `vulnerabilities` and a count per practice. One facet statement
  over the caller's scoped WHERE (`findings:read`, heavy-read limit, 5 s), so
  each count equals that list's total for the same caller
  (`findings_practice_counts_db_test.go`).
- `compliance_result` is an ordinary filter in the filter picker (pass, fail,
  manual, not_applicable, error, unknown).
- Settings > SLA policies: a new policy is created for Vulnerabilities or
  Compliance (Compliance starts from the compliance windows); the list marks
  compliance policies.

## Existing rows: the `finding-practice` command (shipped)

Rows written before the column read as `other` with a NULL reason until the
backfill runs; a new sighting of an open one derives it. The operator command
`finding-practice` (a link to the server binary in the API image,
`api/internal/tools/findingpractice`) sets them:

- It considers every finding never derived (any status) and every open
  finding (to catch changed inputs); a closed finding that has a practice is
  never touched.
- It derives with the same `DerivePractice` as the write path, reading the
  asset facts through a join pinned to the tenant.
- **A dry run is the default**: the connection is read-only and the report
  holds aggregates only, per tenant: findings per practice before and after,
  the moves between practices (open and closed counts), the rows that would
  change and their reason codes. No finding id or content is printed.
- `-apply` writes keyset pages of 2 000 (`-batch`), one transaction each, only
  where the stored value differs, so a rerun is a no-op; it queues a dashboard
  fact refresh for the assets whose findings moved. A written row gets a new
  `updated_at` and `row_version`, like every write.
- `-tenant <id>` limits the run to one tenant; `-json` prints the report as
  JSON.

```
finding-practice                 # dry run, every tenant
finding-practice -tenant <id>    # dry run, one tenant
finding-practice -apply          # write (owner's go on production)
```

## Compliance SLA (shipped)

Compliance findings have their own SLA policy, so their windows never reach
vulnerability SLA figures and vulnerability windows never reach them.

- `sla_policies.practice`: NULL (the policy governs every finding except
  compliance, as every policy before) or `compliance` (it governs only
  compliance findings). Fixed at create (`POST /api/v1/sla-policies` with
  `"practice": "compliance"`); one default per tenant and practice (unique
  index `uq_sla_policies_tenant_default` on `(tenant_id, COALESCE(practice, ''))`).
- Resolution for a compliance finding: the asset's compliance policy, else the
  tenant's default compliance policy, else the platform compliance windows
  (`sladom.DefaultCompliancePriorityDays`: P0 30, P1 30, P2 90, P3 180 days;
  per severity critical 30, high 30, medium 90, low 180, info none). A policy
  without a practice never governs it; the known exploited cap never applies
  (a check has no CVE). Every other finding keeps the existing choice (asset,
  tenant default, platform), and a compliance policy never governs it.
- The choice is made in one place (`sla.Service.policyResolver`, keyed by
  practice) and used by ingest (`Applier.ApplyBatch`), the severity-downgrade
  relaxation, the deadline explanation on the finding page, the acceptance
  expiry, the material-change reopen and the regression restart.
- Deadlines stay tighten-only: a compliance finding stored with a shorter
  vulnerability deadline keeps it until the explicit re-baseline below.
- **Re-baseline** (`finding-practice -sla`): for every open compliance finding
  with a deadline, the compliance deadline counted from first detection. A dry
  run (the default) reports per tenant the findings considered, those whose
  deadline would move later and by how many days in all, those unchanged, and
  the overdue count before and after. `-sla -apply -undo <file>` first writes
  the undo file (tenant, finding, previous deadline and status, new deadline;
  never overwritten), then moves only deadlines still as read to the later
  date (never earlier), in a transaction marked as an explicit SLA change so
  the tighten-only guard lets it through, with an `sla_rebaselined` timeline
  entry per finding carrying both deadlines. A rerun changes nothing.
- Dashboard figures are vulnerability figures: every dashboard query over
  findings (`findingExcl`) and the dashboard facts (`dash_recompute_asset`)
  leave compliance findings out, and a practice change marks the asset for a
  fact refresh. The findings list's own counts follow its filters (the
  practice switch).

## Key files

- `api/pkg/domain/vulnerability/practice.go`, `practice_test.go`
- `api/internal/infra/postgres/finding_practice_columns.go`
- `api/migrations/*_finding_practice*.sql`
- `api/internal/infra/http/routes/findings_practice_filter_db_test.go`
- `api/internal/tools/findingpractice` (the backfill command)
- `api/internal/infra/http/handler/finding_practice_counts_handler.go`, `web/src/features/findings/components/practice-switch.tsx`, `web/src/features/findings/lib/practice.ts`
- `api/pkg/domain/sla/entity.go`, `api/internal/app/sla/service.go` (compliance policy)
- `api/migrations/*_sla_policy_practice.sql`, `*_dashboard_facts_without_compliance.sql`
