-- Where events about a private program's assets may be delivered (RFC-065 §15.4).
--
-- Tenant integrations (Slack, Teams, Telegram, email, webhooks, Splunk HEC)
-- are organization-wide channels. An event about an asset that only private
-- programs list goes only to the integrations a program member attached to
-- one of those programs (bounty_program_channels), unless an owner turned on
-- org_channels_opt_in for every such program.
--
-- Live impact: one boolean column with a constant default (no rewrite), a
-- unique constraint on the small integrations table (it already has a unique
-- id, so it cannot fail), and a new empty table.

ALTER TABLE bounty_programs
    ADD COLUMN IF NOT EXISTS org_channels_opt_in boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN bounty_programs.org_channels_opt_in IS
    'An owner allowed events about the assets of this private program to reach organization-wide integrations';

ALTER TABLE integrations ADD CONSTRAINT uq_integrations_tenant_id UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS bounty_program_channels (
    tenant_id      uuid        NOT NULL,
    program_id     uuid        NOT NULL,
    integration_id uuid        NOT NULL,
    created_by     uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, program_id, integration_id),
    CONSTRAINT fk_bounty_program_channels_program FOREIGN KEY (tenant_id, program_id)
        REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_bounty_program_channels_integration FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_bounty_program_channels_integration
    ON bounty_program_channels (tenant_id, integration_id);

COMMENT ON TABLE bounty_program_channels IS
    'Integrations a program member attached to a program: they also receive events about its private assets';
