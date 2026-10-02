-- Down for 000213: move the quarantined tables back to public — fully reversible,
-- zero loss. Because phase 1 only relocated the tables (SET SCHEMA), everything —
-- rows, indexes, constraints, RLS policies, in/out FKs — is restored intact simply
-- by moving them back. No CREATE TABLE / DDL replay is required.

ALTER TABLE IF EXISTS deprecated.agent_metrics                  SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.email_logs                     SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.registration_tokens            SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.scan_profile_template_sources  SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.threat_actor_cves              SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.finding_regression_events      SET SCHEMA public;
ALTER TABLE IF EXISTS deprecated.agent_audit_logs               SET SCHEMA public;

-- Remove the now-empty quarantine schema. Bare DROP (no CASCADE): if anything
-- unexpected still lives in `deprecated`, this errors loud rather than deleting it.
DROP SCHEMA IF EXISTS deprecated;
