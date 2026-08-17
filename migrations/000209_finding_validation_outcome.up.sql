-- Migration 000209: Validation confirm-or-downgrade verdict (RFC-011.2 Phase 2a)
--
-- Records the outcome of a validation re-check on the finding itself so the
-- CTEM "downgrade %" outcome metric becomes real (was rendered "not measured"
-- on the Program-Health board). Two additive, nullable columns:
--
--   validation_outcome : the latest verdict from a validation re-check —
--                        'reproducible' (still exploitable / detected) or
--                        'not_reproducible' (exposure no longer observable).
--                        NULL for findings never validated (back-compat).
--   downgraded_at      : set the moment a still-open finding is downgraded to
--                        the validated_fixed state after a 'not_reproducible'
--                        verdict. Durable — it survives the later human close,
--                        so the downgrade % denominator/numerator stay correct.
--
-- The finding state machine gains a 'validated_fixed' status value; the
-- findings.status CHECK constraint was dropped in 000095 (validation moved to
-- the Go domain layer), so no constraint change is needed for the new state.
--
-- NOTE (migration numbering): sibling PRs took 000207 (asset_cia_controlplane)
-- and 000208 (ctem_id_catalog) on develop, so this pair was renumbered to 000209.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_outcome VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS downgraded_at TIMESTAMPTZ;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_validation_outcome;
ALTER TABLE findings ADD CONSTRAINT chk_findings_validation_outcome
    CHECK (validation_outcome IS NULL OR validation_outcome IN ('reproducible', 'not_reproducible'));

-- Partial index for the downgrade-count metric query (only the small set of
-- downgraded findings is indexed).
CREATE INDEX IF NOT EXISTS idx_findings_downgraded
    ON findings (tenant_id)
    WHERE downgraded_at IS NOT NULL;
