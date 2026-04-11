-- Make findings.asset_id optional.
--
-- Rationale: pentest findings often target subjects that aren't (yet) in the
-- asset inventory — newly-discovered subdomains, ephemeral cloud resources,
-- social engineering targets, physical security observations, etc. Forcing
-- asset_id NOT NULL blocks these legitimate findings from being recorded.
--
-- Scanner findings continue to provide asset_id at the application layer
-- (the discovery loop guarantees the asset exists before the finding is
-- emitted), so this only relaxes a constraint pentest needed.
--
-- Free-text asset references remain available via:
--   - findings.source_metadata.affected_assets (JSONB list)
-- and ensure CTEM dashboards can still surface unlinked findings via the
-- "source = pentest" filter.

ALTER TABLE findings
    ALTER COLUMN asset_id DROP NOT NULL;

-- Index used by per-asset finding lookups still works for non-null rows.
-- Add a partial index to keep performance for the common case.
CREATE INDEX IF NOT EXISTS idx_findings_asset_id_notnull
    ON findings(asset_id, status)
    WHERE asset_id IS NOT NULL;
