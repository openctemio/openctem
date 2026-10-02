-- =============================================================================
-- Migration 107: Backfill bad `deployed_to` relationship rows
--
-- ⚠ REVIEW BEFORE APPLYING ⚠
-- This migration mutates production relationship data. Read the rationale,
-- inspect the affected rows on a non-prod copy first, and only apply once
-- you've confirmed the conversion makes sense for your tenant.
--
-- WHY:
--   The constraint table for asset relationships used to allow `service`,
--   `api`, and `website` source types for the `deployed_to` relationship.
--   Per CMDB best practice this is wrong: `deployed_to` should be
--   artifact-only (repositories, container images, build outputs).
--   Runtime workloads (services, APIs, websites) belong in `runs_on`.
--
--   The frontend constraint table and the backend placement-mutex check
--   were tightened in the matching feature commit, so NEW data can no
--   longer end up in this state. This migration cleans up EXISTING rows
--   that were created under the loose rules.
--
-- WHAT:
--   For every `deployed_to` row whose source asset type is service,
--   api, or website (the "wrong" cases), we either:
--     (a) DELETE the row if a `runs_on` row already exists for the same
--         tenant + source + target pair (the user already has the
--         "correct" edge — the deployed_to one is pure noise);
--     (b) UPDATE the row's relationship_type from `deployed_to` to
--         `runs_on` if no such `runs_on` exists yet (preserve the user's
--         intent: they recorded a placement; we just relabel it).
--
--   We keep description, confidence, impact_weight, tags, and
--   timestamps unchanged in case (b). The asset_relationships unique
--   constraint is `(tenant_id, source_asset_id, target_asset_id,
--   relationship_type)` so the (b) update can never collide.
--
-- HOW TO INSPECT FIRST (run on a copy of your DB):
--
--     SELECT r.id, r.tenant_id, r.source_asset_id, r.target_asset_id,
--            sa.asset_type AS source_type, ta.asset_type AS target_type,
--            r.created_at
--     FROM asset_relationships r
--     JOIN assets sa ON sa.id = r.source_asset_id
--     JOIN assets ta ON ta.id = r.target_asset_id
--     WHERE r.relationship_type = 'deployed_to'
--       AND sa.asset_type IN ('service', 'api', 'website');
--
-- =============================================================================

BEGIN;

-- Step (a): delete deployed_to rows whose source is service/api/website
-- AND a corresponding runs_on row already exists between the same pair.
-- These are pure duplicates of the canonical edge.
DELETE FROM asset_relationships AS d
USING assets AS sa
WHERE d.relationship_type = 'deployed_to'
  AND d.source_asset_id = sa.id
  AND sa.asset_type IN ('service', 'api', 'website')
  AND EXISTS (
      SELECT 1
      FROM asset_relationships r2
      WHERE r2.relationship_type = 'runs_on'
        AND r2.tenant_id = d.tenant_id
        AND r2.source_asset_id = d.source_asset_id
        AND r2.target_asset_id = d.target_asset_id
  );

-- Step (b): relabel the remaining deployed_to rows where source is
-- service/api/website to runs_on. Safe because the unique constraint
-- already excluded the (tenant, source, target, runs_on) tuple per
-- step (a).
UPDATE asset_relationships AS d
SET relationship_type = 'runs_on',
    updated_at        = NOW()
FROM assets AS sa
WHERE d.relationship_type = 'deployed_to'
  AND d.source_asset_id = sa.id
  AND sa.asset_type IN ('service', 'api', 'website');

COMMIT;
