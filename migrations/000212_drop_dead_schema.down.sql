-- Down for 000212: restore the dropped schema shape (STRUCTURE ONLY).
--
-- Data is intentionally NOT restored, and none is lost: the CIA columns and
-- findings.finding_number were 100% NULL when dropped, and _bak_ine_20260803 was
-- itself a throwaway backup. Re-adding the empty structures fully reverses the
-- schema change with no data implications.

-- 1. CIA columns on assets — same VARCHAR(10) + CHECK as migration 000150.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS confidentiality_impact VARCHAR(10)
  CHECK (confidentiality_impact IS NULL OR confidentiality_impact IN ('none','low','moderate','high'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS integrity_impact VARCHAR(10)
  CHECK (integrity_impact IS NULL OR integrity_impact IN ('none','low','moderate','high'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS availability_impact VARCHAR(10)
  CHECK (availability_impact IS NULL OR availability_impact IN ('none','low','moderate','high'));

-- 2. finding_number column + its partial index — same as migration 000119.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_number INT;
CREATE INDEX IF NOT EXISTS idx_findings_campaign_number
    ON findings(pentest_campaign_id, finding_number DESC)
    WHERE pentest_campaign_id IS NOT NULL AND finding_number IS NOT NULL;

-- 3. _bak_ine_20260803 — recreate the empty backup table. The original was made
--    out-of-band with CREATE TABLE ... AS SELECT * FROM
--    integration_notification_extensions, which copies column TYPES only (no
--    PK / FK / defaults), so we restore that plain, constraint-free shape.
CREATE TABLE IF NOT EXISTS _bak_ine_20260803 (
    integration_id       UUID,
    enabled_severities   TEXT[],
    enabled_event_types  TEXT[],
    message_template     TEXT,
    include_details      BOOLEAN,
    min_interval_minutes INTEGER
);
