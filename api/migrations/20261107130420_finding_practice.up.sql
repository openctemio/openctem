-- Finding practice: the programme that triages a finding
-- (docs/architecture/finding-practices.md).
--
-- practice is derived in Go (vulnerability.DerivePractice) when a finding is
-- written; practice_reason is the code of the rule that set it, NULL for a
-- row written before this migration (never derived). Existing rows read as
-- 'other' until the operator runs the finding-practice command, which is a
-- dry run unless given -apply.
--
-- Live impact: ADD COLUMN with a constant default is a catalog change (no
-- table rewrite). The CHECK is added NOT VALID, then validated, which scans
-- the table under SHARE UPDATE EXCLUSIVE (reads and writes continue).
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS practice varchar(16) NOT NULL DEFAULT 'other',
    ADD COLUMN IF NOT EXISTS practice_reason varchar(120);

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_practice CHECK (practice IN
        ('aspm', 'infra', 'external', 'cloud', 'compliance', 'offensive', 'identity', 'runtime', 'other')) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_practice;

COMMENT ON COLUMN findings.practice IS
    'Programme that triages the finding: aspm, infra, external, cloud, compliance, offensive, identity, runtime, other. Derived in Go at write time (vulnerability.DerivePractice); compliance means finding_type = compliance.';
COMMENT ON COLUMN findings.practice_reason IS
    'Code of the derivation rule that set practice; NULL = never derived (written before the column existed).';
