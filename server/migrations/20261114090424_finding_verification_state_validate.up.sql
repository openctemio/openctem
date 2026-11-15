-- Validate the two CHECKs finding_verification_state added NOT VALID.
-- In their own migration because the runner applies one file per
-- transaction: validated in the ALTER's file, both table scans would run
-- while that transaction still held the ALTER's ACCESS EXCLUSIVE lock.
-- Here VALIDATE takes only SHARE UPDATE EXCLUSIVE: reads and writes of
-- findings go on during the scans, and every existing row already passes
-- (verification_state 'unchecked', hold_reasons empty, by default).
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_verification_state;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_hold_reasons;
