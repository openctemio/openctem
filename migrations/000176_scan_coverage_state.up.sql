-- Scan coverage rotation cursor (RFC-007 Phase 3).
--
-- The general `assets` table has no per-asset scan-recency cursor (only the
-- git-centric asset_repositories/repository_branches tables do). The
-- license-aware coverage scheduler needs one so it can rotate through a large
-- estate oldest-first without re-picking the same hosts every cycle.
--
-- This table is the durable cursor: one row per asset that has been dispatched
-- for coverage at least once. Assets with no row are treated as never-scanned
-- (they sort first). It is intentionally separate from `assets` so scanner
-- orchestration state never bloats the core asset entity.
--
-- NOTE: active-IP accounting for capped engines (Tenable.sc) is NOT modelled
-- here yet — that lands with the .sc reclaim-ACK work (Phase 3.5). Today the
-- scheduler only drives unlimited engines (Nessus Pro), for which a cursor is
-- all that is required.
CREATE TABLE IF NOT EXISTS scan_coverage_state (
    asset_id           UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    last_dispatched_at TIMESTAMPTZ NOT NULL,
    last_session_id    TEXT,
    last_command_id    UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rotation lookup: oldest-dispatched first within a tenant. (Never-scanned
-- assets have no row at all, so they are found by the LEFT JOIN, not this index.)
CREATE INDEX IF NOT EXISTS idx_scan_coverage_rotation
    ON scan_coverage_state (tenant_id, last_dispatched_at ASC);
