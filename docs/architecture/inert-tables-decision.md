# Inert tables — wire-or-drop decision

A DB-redundancy audit (2026-08) found seven tables that exist in the migration
schema but have **no writer** (nothing in the Go codebase ever `INSERT`s into
them) and, in most cases, no reader either. They are not touched by migration
`000212_drop_dead_schema` — unlike the columns and orphan backup table dropped
there, each of these needs a product decision (wire it up, or drop it), so they
are recorded here for a follow-up rather than removed blind.

Verification for every row below: `grep -rn "INSERT INTO <table>"` over
`*.go` = 0 writers, and `grep -rin "<table>"` over `*.go` = the "Go refs" count.

| Table | Created by | Why inert | Recommendation |
|-------|-----------|-----------|----------------|
| `agent_audit_logs` | `000021_audit_logs.up.sql` | Purpose-built agent-audit table (agent_id, api_key_id, event_type/action/status, duration_ms, …). 0 Go refs — no writer, no reader. The related `AuditService.LogAgentConnected/LogAgentDisconnected` methods (`internal/app/audit/service.go`) exist but have **no callers**, and even they route to the generic `audit_logs` via `LogEvent`, not to this table. | **WIRE.** Clear intent exists: a dedicated schema plus `docs/architecture/agent-audit-logging.md`, which specifies agent-lifecycle auditing and itself flags these methods as never called. Wiring means calling the lifecycle hooks from the agent/platform-agent service and directing them at `agent_audit_logs`. |
| `finding_regression_events` | `000152_business_services_and_regression.up.sql` | 0 Go refs — no writer, no reader. The regression signal is actually carried on `findings.is_regression` / `reopen_count` (17 Go refs, exercised by `finding_regression_db_test.go`); the dedicated events table was never populated. (Note: an earlier belief that the executive dashboard reads this table does **not** hold on current `develop` — it reads the `findings` columns.) | **WIRE.** Append one event row when `is_regression` flips true, to get a regression **history/timeline** the boolean alone can't provide. If a per-event history is judged unnecessary, this becomes a DROP instead — but that is a product call, not an audit one. |
| `agent_metrics` | `000016_agents.up.sql` | 0 Go refs — no writer, no reader. Agent metrics are not collected through this table. | **DROP** (obsolete/superseded). |
| `email_logs` | `000021_audit_logs.up.sql` | 0 Go refs — no writer, no reader. Outbound email is not journaled here. | **DROP** (obsolete/superseded). |
| `registration_tokens` | `000016_agents.up.sql` | 0 Go refs — no writer, no reader. Agent registration/bootstrap uses the agent-identity / bootstrap-token path, not this table. | **DROP** (superseded by the agent-identity bootstrap flow). |
| `scan_profile_template_sources` | `000029_finding_data_flows.up.sql` | 0 Go refs — no writer, no reader. Scan-profile templates do not resolve through a sources table. | **DROP** (obsolete/superseded). |
| `threat_actor_cves` | `000121_threat_actors.up.sql` | 0 Go refs — no writer, no reader. Threat-actor ↔ CVE association is not persisted via this join table. | **DROP** (obsolete/superseded). |

## Why they are NOT in `000212`

`000212_drop_dead_schema` only removes schema that is unambiguously safe and
needs no product judgement: three superseded `assets` CIA columns (100% NULL,
0 Go readers, replaced by `impact_confidentiality/…`), the never-wired
`findings.finding_number` column (100% NULL, 0 Go readers), and the orphan
out-of-band backup table `_bak_ine_20260803`.

The seven tables above are different: two (`agent_audit_logs`,
`finding_regression_events`) have latent, half-built intent that is arguably
worth completing, and dropping the other five, while low-risk, removes a table
other pods could theoretically query and so belongs in its own reviewed change
(expand-contract "contract" step) rather than being bundled here. Each DROP,
when actioned, should follow the same `-- expand-contract-ok:` marker path that
`000212` uses.
