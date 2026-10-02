-- Migration 000151: Freshness SLA + Process Metrics (Phase 2)
--
-- Asset freshness SLA: configurable per-tenant re-scan intervals.
-- Process metrics views for approval velocity, retest times.

-- Freshness SLA settings on tenant (stored in tenant settings JSONB)
-- No new table needed — uses existing tenant.settings JSONB field:
--   settings.asset_freshness = {
--     "external_days": 1,
--     "internal_days": 7,
--     "cloud_days": 3,
--     "default_days": 7
--   }

-- Stale asset detection index
CREATE INDEX IF NOT EXISTS idx_assets_stale_check
  ON assets(tenant_id, last_seen, exposure)
  WHERE status != 'archived';

-- Process metrics: approval velocity (how fast approvals are processed)
-- Uses existing finding_status_approvals table — add index for time queries
CREATE INDEX IF NOT EXISTS idx_approval_velocity
  ON finding_status_approvals(tenant_id, created_at DESC)
  WHERE status IN ('approved', 'rejected');

-- Add freshness_status computed column via expression index for fast queries
-- (stale if last_seen < now() - interval based on exposure type)
-- This is a materialized approach — the SLA escalation controller can update a simple field instead
ALTER TABLE assets ADD COLUMN IF NOT EXISTS freshness_status VARCHAR(20) DEFAULT 'fresh'
  CHECK (freshness_status IS NULL OR freshness_status IN ('fresh', 'stale', 'unknown'));
