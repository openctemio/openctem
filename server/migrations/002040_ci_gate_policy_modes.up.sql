-- Per-capability and per-rule modes of a CI gate policy (RFC-077 G-7):
-- {"capabilities": {"sast": "block|comment|monitor", ...}, "rules": {"<rule id>": "..."}}.
ALTER TABLE ci_gate_policies ADD COLUMN IF NOT EXISTS modes JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_modes;
ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_modes CHECK (jsonb_typeof(modes) = 'object');
