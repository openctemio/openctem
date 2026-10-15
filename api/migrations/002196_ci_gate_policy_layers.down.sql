ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_baseline_grace;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_reason;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_layer;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_fields;
ALTER TABLE ci_gate_policies
    DROP COLUMN IF EXISTS baseline_secrets_block,
    DROP COLUMN IF EXISTS baseline_grace_days,
    DROP COLUMN IF EXISTS baseline_on_first_run,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS locked_fields,
    DROP COLUMN IF EXISTS fields;
