-- Recreate the columns dropped by 001062 with their original definitions.
-- They come back with their defaults; they held nothing else.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS compliance_requirements TEXT[],
    ADD COLUMN IF NOT EXISTS last_assessment_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_assessment_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS freshness_status VARCHAR(20) DEFAULT 'fresh'
        CONSTRAINT assets_freshness_status_check
        CHECK (freshness_status IS NULL OR freshness_status IN ('fresh', 'stale', 'unknown'));

ALTER TABLE pipeline_templates ADD COLUMN IF NOT EXISTS ui_positions JSONB DEFAULT '{}';
