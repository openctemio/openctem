-- RFC-021 Phase-1b: dashboards carry a description and a column-count layout
-- structure (1..4 equal columns). Both have safe defaults so the pre-migration
-- binary keeps working (extra columns ignored).
ALTER TABLE user_dashboards
    ADD COLUMN IF NOT EXISTS description   TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS column_count  SMALLINT NOT NULL DEFAULT 2;
