# RFC-115: Custom query language

| | |
|---|---|
| Status | Accepted (2026-10-18). Partly implemented: the language, findings and assets, the plan layer, the PostgreSQL executor and the explain/run/schema endpoints have shipped (§7) |
| Scope | api (`pkg/querylang`, `pkg/querylang/pgsql`, `internal/app/query`, `POST /api/v1/query/explain`, `POST /api/v1/query/run`, `GET /api/v1/query/schema`); later web (editor, builder, widgets) |
| Related | RFC-048 (list query contract, filterspec), RFC-065 (bug-bounty program visibility), the dashboard redesign; `docs/architecture/query-language.md` |

## 1. Problem

People ask questions of their data that no built-in widget answers: "open
critical KEV findings on internet-facing assets older than two weeks", "open
findings by business unit and priority", "new external assets per day". They
want the answer as a number, a table or a trend, and later as a dashboard
widget, a scheduled report section or an alert. The answer must never include
rows the asker may not see.

## 2. Options

| Option | Verdict |
|---|---|
| Structured builder only (a UI over the filter document) | kept as a first-class editor of the same document, but too slow for experts, no aggregation, hard to share as text |
| **Small text language compiled to the filterspec AST plus an aggregation pipeline** | **chosen**: pasteable, diffable, versionable; one compiler keeps the allowlist and every server-side rule; builder and text are two views of one document |
| Raw SQL | rejected: tenant, data scope and pentest rules cannot be guaranteed (row-level security is in shadow mode), every table and column is exposed, schema changes break saved queries, unbounded cost |

## 3. Decision

- **Language**: `entity [where filter] | stage | ...` with a fixed grammar
  (architecture doc). Fields, operators and enum values come only from the
  entity's filterspec registry; relations are curated (finding → asset).
- **Compilation path**: text → AST (with byte positions) → version 1
  FilterDocument → `filterspec.ParseDocument` (typing, enums, limits) →
  `Plan` → executor. Errors from any step map back to the text.
- **Plan layer owns security**: the plan carries the filterspec actor (tenant,
  data scope, member visibility), the entity's mandatory filters and the
  already-applied entity and field permission checks. Executors read the plan;
  they cannot build one or drop a rule.
- **Executors**: an `Executor` interface (`Explain`, `Run`). PostgreSQL is the
  only backend (raw tables now, the per-asset fact tables as a faster path
  later). No other datastore is added; a columnar backend could implement the
  same interface later without changing the language, the API or the rules.
- **Mandatory filters**: drafts and in-review pentest findings, branch-only
  findings, bug-bounty program assets (and their findings) and deleted assets
  are left out of every query. A query cannot mention the internal fields.
- **Cost**: input limits, a complexity score, group and row caps, a READ ONLY
  transaction with a 5 s statement timeout and a `work_mem` cap, a per-user
  rate limit and per-user / per-tenant concurrency caps.
- **Document v2** = FilterDocument v1 + `entity` + `pipeline`; the
  server-side filters are not stored in it.

## 4. Security and threat model

See the architecture doc ("Security model", "Threat model"). In short: no SQL
in the grammar, registry constants and bound parameters only, the principal
comes from the authenticated request, forbidden fields answer exactly like
unknown ones, and every statement starts with the tenant predicate. Tests:
parser and compiler fuzzing (committed seeds), golden text → SQL files,
injection and bypass attempts, permission and pentest non-member cases,
cross-tenant and data-scope DB tests, cost-limit and timeout tests.

## 5. Not in this version

Saved queries (stored on the saved views table with immutable versions,
sharing and audit), the fact-table planner and cost estimator,
query-bound widgets and drill-down, daily results for raw trend widgets, the
web editor with autocomplete, the query explorer page and export, alert rules,
the query library, row lists (`fields`), and the entities EASM changes, scans,
sensors, remediation and audit.

## 6. Open questions

- Distributed concurrency limits (the caps are per API process today).
- Hourly cost-unit quotas by edition (needs the cost estimator).

## 7. Implementation

- Language, findings and assets entities, plan layer, PostgreSQL executor,
  explain/run/schema endpoints: this RFC's first pull request.
