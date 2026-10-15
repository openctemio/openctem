-- Per-field layering of CI gate policies (docs/rfcs/RFC-095-ci-per-repository-settings.md):
-- a business unit or repository policy sets only the fields it lists and inherits the rest;
-- organization and business unit policies can lock fields; a repository policy carries a
-- reason and can expire. The gate baseline settings join the policy. Existing rows set every field, which keeps their behaviour.

ALTER TABLE ci_gate_policies
    ADD COLUMN IF NOT EXISTS fields TEXT[] NOT NULL DEFAULT ARRAY['mode', 'fail_on_severity', 'new_findings_only', 'fail_on_kev', 'epss_threshold',
        'fixable_only', 'modes', 'allow_repo_policy', 'baseline_on_first_run', 'baseline_grace_days',
        'baseline_secrets_block']::text[],
    ADD COLUMN IF NOT EXISTS locked_fields TEXT[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS baseline_on_first_run BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS baseline_grace_days INTEGER,
    ADD COLUMN IF NOT EXISTS baseline_secrets_block BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_baseline_grace;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_baseline_grace CHECK (
    baseline_grace_days IS NULL OR baseline_grace_days BETWEEN 1 AND 730);

ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_fields;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_fields CHECK (
    fields <@ ARRAY['mode', 'fail_on_severity', 'new_findings_only', 'fail_on_kev', 'epss_threshold',
        'fixable_only', 'modes', 'allow_repo_policy', 'baseline_on_first_run', 'baseline_grace_days',
        'baseline_secrets_block']::text[]
    AND locked_fields <@ ARRAY['mode', 'fail_on_severity', 'new_findings_only', 'fail_on_kev', 'epss_threshold',
        'fixable_only', 'modes', 'allow_repo_policy', 'baseline_on_first_run', 'baseline_grace_days',
        'baseline_secrets_block']::text[]);

-- Locks only above repositories; expiry only on repositories.
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_layer;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_layer CHECK (
    (scope_type <> 'repository' OR cardinality(locked_fields) = 0)
    AND (scope_type = 'repository' OR expires_at IS NULL));

ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_reason;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_reason CHECK (char_length(reason) <= 500);

COMMENT ON COLUMN ci_gate_policies.fields IS 'Fields this policy sets; the others are inherited from the layer above.';
COMMENT ON COLUMN ci_gate_policies.locked_fields IS 'Fields no layer below may loosen (organization and business unit policies).';
COMMENT ON COLUMN ci_gate_policies.reason IS 'Why a repository policy differs from what it inherits.';
COMMENT ON COLUMN ci_gate_policies.expires_at IS 'A repository policy stops applying at this time (NULL: no end).';
