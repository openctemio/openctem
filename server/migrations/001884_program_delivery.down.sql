DROP TABLE IF EXISTS bounty_program_channels;
ALTER TABLE integrations DROP CONSTRAINT IF EXISTS uq_integrations_tenant_id;
ALTER TABLE bounty_programs DROP COLUMN IF EXISTS org_channels_opt_in;
