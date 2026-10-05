-- Template provenance of a finding's last sighting (research/18 O6
-- "template digest drift → inconclusive"; sensor#134).
--
-- The sensor reports, per nuclei finding, the sha256 of the template file
-- that matched (properties.template_digest) and its path, and per report
-- the nuclei-templates release it scanned with (tool.properties.content:
-- version + archive digest). Ingest keeps the last sighting's values here,
-- so a retest or a later scan that ran different template content cannot
-- close the finding: a retest whose template digest differs (or is
-- missing) is inconclusive, and a covered scan with a different release
-- marks the finding not_observed, until a new sighting re-baselines it.
--
-- Additive, nullable, no default: no rewrite of the findings table. NULL =
-- no provenance recorded (older sensors, other tools): the previous rules
-- apply. Values are validated in the application; the CHECK is added NOT
-- VALID, so it binds every new write without scanning the populated table
-- (every existing row is NULL in these columns and would pass anyway).

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS template_digest text,
    ADD COLUMN IF NOT EXISTS template_path text,
    ADD COLUMN IF NOT EXISTS templates_version text,
    ADD COLUMN IF NOT EXISTS templates_digest text,
    ADD COLUMN IF NOT EXISTS template_seen_at timestamptz;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS chk_findings_template_provenance;
ALTER TABLE findings
    ADD CONSTRAINT chk_findings_template_provenance CHECK (
        (template_digest IS NULL OR template_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (templates_digest IS NULL OR templates_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (template_path IS NULL OR length(template_path) <= 512)
        AND (templates_version IS NULL OR length(templates_version) <= 64)
    ) NOT VALID;

COMMENT ON COLUMN findings.template_digest IS 'sha256 of the template file that matched at the last sighting (sensor properties.template_digest); research/18 O6.';
COMMENT ON COLUMN findings.template_path IS 'Path of that template inside the release (properties.template_path).';
COMMENT ON COLUMN findings.templates_version IS 'Template release the last sighting ran with (tool.properties.content).';
COMMENT ON COLUMN findings.templates_digest IS 'Archive digest of that release.';
COMMENT ON COLUMN findings.template_seen_at IS 'When the template provenance was last recorded.';
