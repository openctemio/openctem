-- CTEM Stage-4: "did our controls react?"
--
-- The platform could already answer "is the exposure still reachable?"
-- (validation_evidence.outcome). It could NOT answer the other Stage-4
-- question — whether anything in the defensive stack OBSERVED the
-- validation. This migration adds the two pieces that question needs:
--
--   1. runtime_telemetry_events.correlation_id — a key a telemetry
--      producer stamps so an event can be tied to the validation job
--      that provoked it. Exact correlation; no time heuristics needed.
--
--   2. validation_evidence.detection_status — the detection verdict,
--      in a vocabulary DELIBERATELY DISJOINT from outcome.
--
-- Why a separate column and a separate vocabulary, not more outcome
-- values: `outcome` already uses the words 'detected' / 'not_detected'
-- to mean "the exposure was/was not still reachable". That is a
-- statement about the TARGET. The detection verdict is a statement
-- about our SENSORS. Reusing the words would make every stored row
-- ambiguous about which question it answers — and the two questions
-- have opposite polarity (outcome='detected' is bad news,
-- detection='observed' is good news). No value below appears in the
-- outcome CHECK constraint, and none of the outcome values appear
-- here, so a value can never be read against the wrong question.

ALTER TABLE runtime_telemetry_events
    ADD COLUMN IF NOT EXISTS correlation_id UUID;

COMMENT ON COLUMN runtime_telemetry_events.correlation_id IS
    'Optional key linking this event to the validation job/command that provoked it. Stamped by the telemetry producer (EDR/XDR forwarder) and echoed from the ingest API. NULL for ordinary background telemetry.';

-- Partial index: correlation lookups are always tenant-scoped and only
-- ever touch stamped rows, which are a tiny minority of the stream.
CREATE INDEX IF NOT EXISTS idx_rte_correlation
    ON runtime_telemetry_events (tenant_id, correlation_id)
    WHERE correlation_id IS NOT NULL;

ALTER TABLE validation_evidence
    ADD COLUMN IF NOT EXISTS detection_status VARCHAR(24) NOT NULL DEFAULT 'not_evaluated';

ALTER TABLE validation_evidence
    ADD COLUMN IF NOT EXISTS detection_detail JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 'not_evaluated' is the default so every PRE-EXISTING row stays
-- honest: those validations ran before detection correlation existed,
-- so we genuinely do not know and must not backfill a verdict.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_validation_evidence_detection_status'
    ) THEN
        ALTER TABLE validation_evidence
            ADD CONSTRAINT chk_validation_evidence_detection_status CHECK (detection_status IN (
                -- telemetry correlated to this validation arrived → a sensor saw it
                'observed',
                -- telemetry IS flowing for this tenant, but none correlated → real detection gap
                'not_observed',
                -- no telemetry reaching the platform at all → UNKNOWN, not a failure
                'no_telemetry_source',
                -- the validation itself did not execute (error/skipped) → nothing to detect
                'not_applicable',
                -- correlation was not wired/run for this row (incl. all historical rows)
                'not_evaluated'
            ));
    END IF;
END $$;

COMMENT ON COLUMN validation_evidence.detection_status IS
    'Did any control/sensor observe this validation? Distinct question from outcome (which answers "is the exposure still reachable"). no_telemetry_source means UNKNOWN — absence of telemetry is a configuration gap, never proof a control failed.';

COMMENT ON COLUMN validation_evidence.detection_detail IS
    'How the detection verdict was reached: match_mode, correlation window bounds, matched event count, telemetry pipeline liveness. Lets an operator audit a verdict instead of trusting it.';

-- Reads are "show me validations nothing detected", tenant-scoped.
CREATE INDEX IF NOT EXISTS idx_validation_evidence_detection
    ON validation_evidence (tenant_id, detection_status, created_at DESC);
