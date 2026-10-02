# Inert tables — wire-or-drop decision

A DB-redundancy audit (2026-08) found seven tables that exist in the migration
schema but have **no writer** (nothing ever `INSERT`s into them) and no reader.
The initial reading held two of them (`agent_audit_logs`,
`finding_regression_events`) as latent "wire" candidates, but a careful
re-analysis showed both are dead too — the intent they seemed to carry is
actually served elsewhere (see the per-table reasons below). **All seven are
retired via a two-phase, non-destructive process** starting in
`000213_quarantine_obsolete_inert_tables`.

Verification for every row below: `grep -rw "<table>" --include='*.go'` (minus
`/migrations/`) = 0 Go refs, `grep -rw "<table>"` across the `agent`, `sdk-go`,
and `ui` repos and across api's non-Go files (yaml/yml/sql/json/toml, seed
included) = 0, a live `pg_constraint` check = 0 inbound foreign keys, and live
`pg_trigger` / `pg_proc` / `pg_views` scans = 0 DB-internal writers.

## Two-phase retirement (risk-controlled)

**Phase 1 — quarantine (this migration, `000213_quarantine_obsolete_inert_tables`).**
Each table is moved out of `public` into a dedicated `deprecated` schema
(`ALTER TABLE ... SET SCHEMA deprecated`). This removes them from the application
schema (public base-table count 180 → 173) while preserving *everything* — rows,
indexes, constraints, RLS shadow policies, and in/out foreign keys all travel
with the table. It is exactly reversible (the `down` moves them back to `public`)
with zero data loss, and if any unfound consumer exists it fails loud and recovery
is a one-line move-back. This is deliberately NOT a `DROP`.

**Phase 2 — drop (a LATER migration, after a release confirms nothing broke).**
Once a production release has run with the tables quarantined and nothing has
errored, a follow-up migration performs the real removal
(`DROP SCHEMA deprecated CASCADE`). Until then, nothing is destroyed.

Both the direct-DROP dry-run and the SET SCHEMA move were verified error-free on
the live database (transaction + `ROLLBACK`), and every table was 0-row.

| Table | Created by | Why it was safe to drop |
|-------|-----------|-------------------------|
| `agent_metrics` | `000016_agents.up.sql` | Agent performance metrics were never collected through this table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `email_logs` | `000021_audit_logs.up.sql` | Outbound email is not journaled here. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `registration_tokens` | `000016_agents.up.sql` | An early agent-registration table the current code never references. The live, wired agent-key table is `agent_api_keys` (used across ~12 Go files); `registration_tokens` has 0 refs everywhere, 0 rows, 0 inbound FK, 0 writer. (Not claimed to be "superseded by a bootstrap-token flow" — no such table/type was found; the drop stands on the four hard facts.) |
| `scan_profile_template_sources` | `000029_finding_data_flows.up.sql` | Scan-profile templates do not resolve through a sources join table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `threat_actor_cves` | `000121_threat_actors.up.sql` | Threat-actor ↔ CVE association is not persisted via this join table. 0 refs everywhere, 0 rows, no writer/reader, 0 inbound FK. |
| `finding_regression_events` | `000152_business_services_and_regression.up.sql` | **Not a wire candidate — the consumer reads a COLUMN, not this table.** The executive dashboard's `regressions` CTE (`internal/infra/postgres/dashboard_repository.go`) selects `FROM findings WHERE is_regression = true`; the `is_regression` / `reopen_count` / `last_reopened_at` columns are maintained by the `000199` trigger `mark_finding_regression` (which writes those **columns**, never this events table). The table has 0 readers, 0 writers, 0 rows, 0 inbound FK. (`000199` only mentions it in a comment.) |
| `agent_audit_logs` | `000021_audit_logs.up.sql` | **Abandoned design — the audit path uses the shared `audit_logs` table.** `AuditService.LogAgentConnected` / `LogAgentDisconnected` (`internal/app/audit/service.go`) call `LogEvent`, which writes the shared `audit_logs` table, **not** this dedicated one. No api endpoint reads `agent_audit_logs` (the ui `AgentAuditLog` component does not hit it). 0 refs everywhere, 0 rows, 0 inbound FK, 0 writer. |

## Relationship to `000212`

`000212_drop_dead_schema` removed schema that needed no product judgement: three
superseded `assets` CIA columns (100% NULL, 0 Go readers, replaced by
`impact_confidentiality/…`), the never-wired `findings.finding_number` column
(100% NULL, 0 Go readers), and the orphan out-of-band backup table
`_bak_ine_20260803`. `000213` extends that same reviewed `expand-contract`
"contract" path to the seven never-wired **tables** above, each dropped behind
the `-- expand-contract-ok:` marker with a full 0-ref / 0-inbound-FK / 0-writer
proof.
