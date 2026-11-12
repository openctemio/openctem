-- Remediation keys record the version of the key rules that derived them
-- (RFC-015). Version 1 grouped findings by any solution text, so findings of
-- different vulnerabilities that a scanner gave the same boilerplate advice
-- ("Apply the suggested fix code.") shared one key and one suggestion. The
-- suggestion generator now derives a tenant's keys again before it trusts
-- them when any key is older than the current rules.
--
-- Adding a column with a constant default is a catalog-only change: no table
-- rewrite. Every existing key is marked version 1 (unknown), so each tenant's
-- keys are derived once more on the next generator run.
ALTER TABLE finding_remediation_keys
    ADD COLUMN IF NOT EXISTS algorithm_version smallint NOT NULL DEFAULT 1;

COMMENT ON COLUMN finding_remediation_keys.algorithm_version IS
    'Version of the key rules that derived remediation_key; older keys are derived again before a suggestion run uses them.';

-- Open suggestions built on a version-1 key ("sol:<sha256>" with no source
-- part, or "sca:<component>") proposed groups the current rules may not form. They expire
-- now instead of waiting for the next run; a valid group is proposed again
-- by that run from the re-derived keys.
UPDATE remediation_suggestions
SET state = 'expired', version = version + 1, updated_at = now()
WHERE state IN ('proposed', 'snoozed')
  AND (action_key ~ '^sol:[0-9a-f]{64}$' OR action_key LIKE 'sca:%');
