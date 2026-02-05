-- =============================================================================
-- Migration 012: Findings (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_finding_comments_count ON finding_comments;
DROP TRIGGER IF EXISTS trigger_finding_comments_updated_at ON finding_comments;
DROP TRIGGER IF EXISTS trigger_findings_updated_at ON findings;

DROP FUNCTION IF EXISTS update_finding_comments_count();

DROP TABLE IF EXISTS finding_activities;
DROP TABLE IF EXISTS finding_comments;
DROP TABLE IF EXISTS findings;
