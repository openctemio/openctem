-- Held findings: a finding matched while its target was throttling or
-- blocking the scan is kept, with its reasons, but held out of risk scores,
-- SLA escalation, notifications and tickets until it is checked
-- (docs/architecture/held-findings.md).
--
-- verification_state: 'unchecked' (default, every existing row), 'held',
-- 'verified', 'not_reproduced'. hold_reasons: the codes behind a hold
-- (edge_block_page, throttled_response, soft_404, target_throttled,
-- timing_based, oob_weak); empty unless held.
--
-- Live impact: ADD COLUMN with a constant default is a catalog change (no
-- table rewrite, no backfill). The CHECKs are added NOT VALID (no scan), so
-- the ACCESS EXCLUSIVE lock of these ALTERs lasts only for the catalog
-- change. They are validated in finding_verification_state_validate: the
-- runner applies one file per transaction, and a VALIDATE here would scan
-- the table while this file still held that lock.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS verification_state varchar(16) NOT NULL DEFAULT 'unchecked',
    ADD COLUMN IF NOT EXISTS hold_reasons text[] NOT NULL DEFAULT '{}';

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_verification_state CHECK (verification_state IN
        ('unchecked', 'held', 'verified', 'not_reproduced')) NOT VALID;

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_hold_reasons CHECK (
        hold_reasons <@ ARRAY['edge_block_page', 'throttled_response', 'soft_404', 'target_throttled', 'timing_based', 'oob_weak']::text[]
        AND cardinality(hold_reasons) <= 6
        AND (verification_state = 'held' OR cardinality(hold_reasons) = 0)) NOT VALID;

COMMENT ON COLUMN findings.verification_state IS
    'unchecked (default), held (matched while the target throttled or blocked the scan; out of risk scores, SLA escalation, notifications and tickets), verified, not_reproduced.';
COMMENT ON COLUMN findings.hold_reasons IS
    'Codes behind a hold: edge_block_page, throttled_response, soft_404, target_throttled, timing_based, oob_weak. Empty unless verification_state = held.';
