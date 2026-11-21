-- Back to fetched keys only: pasted keys are dropped (an administrator pastes
-- them again after an upgrade).
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_pasted_has_keys;
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_signing_keys_size;
ALTER TABLE ci_trust_configs DROP CONSTRAINT IF EXISTS chk_ci_trust_configs_key_source;
ALTER TABLE ci_trust_configs DROP COLUMN IF EXISTS last_key_id;
ALTER TABLE ci_trust_configs DROP COLUMN IF EXISTS signing_keys_updated_at;
ALTER TABLE ci_trust_configs DROP COLUMN IF EXISTS signing_keys;
ALTER TABLE ci_trust_configs DROP COLUMN IF EXISTS key_source;
