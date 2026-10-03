-- Secret-scanner findings stored as finding_type 'vulnerability' become
-- 'secret' (RFC-044 P0).
--
-- Two causes, both fixed in code:
--   1. Before 528d6fa0 (#823) no finding insert named finding_type, so every
--      row got the column default 'vulnerability' whatever ingest decided.
--   2. A secret scanner's report converted from SARIF (ctis FromSARIF) carries
--      the generic type 'vulnerability' for tools ctis does not recognize as
--      secret scanners (betterleaks), and an explicit CTIS type won over the
--      secret technique. Ingest now types every finding of the secret
--      technique as a secret.
--
-- The rows are selected the way ingest now decides: the secret technique, or
-- a known secret scanner. Only rows still at the default type change.
UPDATE findings
SET finding_type = 'secret'
WHERE finding_type = 'vulnerability'
  AND (source = 'secret'
       OR LOWER(tool_name) IN ('betterleaks', 'gitleaks', 'trufflehog', 'detect-secrets'));
