-- Migration 000212: drop proven-dead schema (DB-redundancy audit, 2026-08).
--
-- expand-contract-ok: contract step — every target below has 0 Go readers and is
-- 100% NULL or an out-of-band backup, so nothing running references it and
-- removing it cannot break an old pod mid-rollout. Full 0-ref proof is in the PR
-- body; each target is IF EXISTS so this migration is idempotent.
--
-- Targets:
--   1. assets.confidentiality_impact / integrity_impact / availability_impact —
--      the migration-000150 CIA predecessors, SUPERSEDED by 000207's
--      impact_confidentiality / impact_integrity / impact_availability (which ARE
--      used). 0 Go readers; 100% NULL.
--   2. findings.finding_number — added by 000119, never wired (no writer, no
--      generator, no default); 0 Go readers; 100% NULL. Its partial index
--      idx_findings_campaign_number is dropped with it.
--   3. _bak_ine_20260803 — an orphan ad-hoc backup of
--      integration_notification_extensions created OUTSIDE the migration system on
--      2026-08-03; unreferenced anywhere in the tree.

-- 1. superseded CIA columns on assets
ALTER TABLE assets DROP COLUMN IF EXISTS confidentiality_impact;
ALTER TABLE assets DROP COLUMN IF EXISTS integrity_impact;
ALTER TABLE assets DROP COLUMN IF EXISTS availability_impact;

-- 2. unwired finding_number column (+ its partial index)
DROP INDEX IF EXISTS idx_findings_campaign_number;
ALTER TABLE findings DROP COLUMN IF EXISTS finding_number;

-- 3. orphan out-of-band backup table
DROP TABLE IF EXISTS _bak_ine_20260803;
