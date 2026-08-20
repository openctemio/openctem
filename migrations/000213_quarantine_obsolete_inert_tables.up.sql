-- Migration 000213: QUARANTINE 7 obsolete, never-wired tables (phase 1 of a
-- two-phase, NON-DESTRUCTIVE retirement). DB-redundancy audit, 2026-08.
--
-- Why quarantine instead of DROP:
-- All 7 tables are provably inert — 0 code refs across api/agent/sdk-go/ui and
-- api non-Go files, 0 rows, 0 inbound foreign key (pg_constraint confrelid = 0),
-- and 0 DB-internal writer (no trigger/function/view). A direct DROP was verified
-- error-free on the live DB. But rather than remove them outright, we first MOVE
-- them into a `deprecated` schema. This:
--   * removes them from `public` (the search_path the app uses) so the application
--     schema is clean — public drops from 180 to 173 base tables — while the app
--     never referenced them anyway;
--   * preserves EVERYTHING (rows, indexes, constraints, RLS shadow policies from
--     000158, and inbound/outbound FKs all travel with SET SCHEMA), so if some
--     unfound consumer exists it fails loud and recovery is a one-line move-back;
--   * is exactly reversible (the down moves them back to public) with zero loss;
--   * leaves a grace period. A later migration performs the real DROP once a
--     release has confirmed in production that nothing depends on them.
--
-- No CASCADE and no policy re-creation are needed: SET SCHEMA is non-destructive
-- and carries dependent objects with the table.
--
-- Targets (created_by + why inert):
--   1. agent_metrics (000016)                 — agent perf metrics never collected here.
--   2. email_logs (000021)                    — outbound email not journaled here.
--   3. registration_tokens (000016)           — early agent-registration table; live
--      wired agent-key table is `agent_api_keys` (~12 Go files).
--   4. scan_profile_template_sources (000029) — scan-profile templates don't resolve
--      through a sources join table.
--   5. threat_actor_cves (000121)             — threat-actor<->CVE not persisted here.
--   6. finding_regression_events (000152)     — the dashboard reads the findings
--      COLUMN is_regression (000199 trigger), never this events table.
--   7. agent_audit_logs (000021)              — agent lifecycle audit goes to the
--      shared audit_logs (LogAgentConnected/Disconnected -> LogEvent), not here.

CREATE SCHEMA IF NOT EXISTS deprecated;
COMMENT ON SCHEMA deprecated IS
    'Quarantined tables pending removal (migration 000213). Kept temporarily for a safe, reversible retirement; a later migration DROPs them once confirmed unused.';

ALTER TABLE IF EXISTS public.agent_metrics                  SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.email_logs                     SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.registration_tokens            SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.scan_profile_template_sources  SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.threat_actor_cves              SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.finding_regression_events      SET SCHEMA deprecated;
ALTER TABLE IF EXISTS public.agent_audit_logs               SET SCHEMA deprecated;
