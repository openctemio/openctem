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

## Existing rows

Rows written before the column read as `other` with a NULL reason until the
backfill runs; a new sighting of an open one derives it.

## Key files

- `api/pkg/domain/vulnerability/practice.go`, `practice_test.go`
- `api/internal/infra/postgres/finding_practice_columns.go`
- `api/migrations/*_finding_practice*.sql`
- `api/internal/infra/http/routes/findings_practice_filter_db_test.go`
