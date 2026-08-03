DROP INDEX IF EXISTS idx_validation_evidence_detection;

ALTER TABLE validation_evidence
    DROP CONSTRAINT IF EXISTS chk_validation_evidence_detection_status;

ALTER TABLE validation_evidence
    DROP COLUMN IF EXISTS detection_detail;

ALTER TABLE validation_evidence
    DROP COLUMN IF EXISTS detection_status;

DROP INDEX IF EXISTS idx_rte_correlation;

ALTER TABLE runtime_telemetry_events
    DROP COLUMN IF EXISTS correlation_id;
