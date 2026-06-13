-- Links a remediation campaign to an external tracker issue (e.g. a Jira epic).
-- A campaign can have at most one ticket per provider (idempotent create).
-- Kept as a side table rather than columns on remediation_campaigns so the
-- campaign aggregate stays stable and additional providers/issues compose.

CREATE TABLE IF NOT EXISTS remediation_campaign_tickets (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id  UUID NOT NULL REFERENCES remediation_campaigns(id) ON DELETE CASCADE,
    provider     VARCHAR(32) NOT NULL DEFAULT 'jira',
    issue_key    VARCHAR(128) NOT NULL,
    issue_url    TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_campaign_ticket_provider UNIQUE (tenant_id, campaign_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_campaign_tickets_campaign
    ON remediation_campaign_tickets (tenant_id, campaign_id);
