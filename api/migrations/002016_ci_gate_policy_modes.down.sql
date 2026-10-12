ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_modes;
ALTER TABLE ci_gate_policies DROP COLUMN IF EXISTS modes;
