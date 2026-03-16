-- =============================================================================
-- Migration 000057: Scan Session Status Expansion
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds 'queued' and 'timeout' statuses to scan_sessions.
-- Standardizes 'cancelled' → 'canceled' (American English).
-- Source: old migration 000149
-- =============================================================================

-- 1. Migrate existing 'cancelled' records to 'canceled'
UPDATE scan_sessions SET status = 'canceled' WHERE status = 'cancelled';

-- 2. Drop old constraint and add expanded one
ALTER TABLE scan_sessions DROP CONSTRAINT IF EXISTS chk_scan_sessions_status;

ALTER TABLE scan_sessions ADD CONSTRAINT chk_scan_sessions_status
    CHECK (status IN ('queued', 'pending', 'running', 'completed', 'failed', 'canceled', 'timeout'));

-- 3. Index for status filtering
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status);
