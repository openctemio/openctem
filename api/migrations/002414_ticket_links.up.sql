-- Ticket links (research 157, RFC-097 related): one row per link between an
-- OpenCTEM object (a finding or a remediation task) and a tracker issue, with
-- the integration that owns the issue. Replaces matching URL strings in
-- findings.work_item_uris and the per-campaign ticket row for the ticket sync:
-- the integration, the issue key and the state are explicit, links are
-- created only by the platform or a person, and every key is tenant-scoped.
--
-- Backfill: Jira browse URLs already on findings, and campaign tickets, whose
-- site matches one of the tenant's Jira integrations. Live: 0 rows of either.
--
-- Live impact: a new table; a unique index on remediation_campaigns (id,
-- tenant_id) (a small table) so links can reference a campaign together with
-- its tenant.

CREATE UNIQUE INDEX IF NOT EXISTS ux_remediation_campaigns_id_tenant
    ON remediation_campaigns (id, tenant_id);

CREATE TABLE IF NOT EXISTS ticket_links (
    id              uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid         NOT NULL,
    integration_id  uuid         NOT NULL,
    provider        varchar(16)  NOT NULL DEFAULT 'jira',
    finding_id      uuid,
    campaign_id     uuid,
    external_id     varchar(64)  NOT NULL DEFAULT '',
    external_key    varchar(64)  NOT NULL,
    project_key     varchar(32)  NOT NULL DEFAULT '',
    url             varchar(2048) NOT NULL,
    role            varchar(16)  NOT NULL DEFAULT 'own',
    state           varchar(16)  NOT NULL DEFAULT 'active',
    source          varchar(16)  NOT NULL,
    created_by      uuid,
    last_status     varchar(128) NOT NULL DEFAULT '',
    last_synced_at  timestamptz,
    sync_error      varchar(500) NOT NULL DEFAULT '',
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ticket_links PRIMARY KEY (id),
    CONSTRAINT fk_ticket_links_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_links_integration_tenant FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_links_finding_tenant FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_links_campaign_tenant FOREIGN KEY (campaign_id, tenant_id)
        REFERENCES remediation_campaigns (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_links_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_ticket_links_one_object CHECK ((finding_id IS NULL) <> (campaign_id IS NULL)),
    CONSTRAINT chk_ticket_links_provider CHECK (provider IN ('jira')),
    CONSTRAINT chk_ticket_links_role CHECK (role IN ('own', 'subtask', 'epic')),
    CONSTRAINT chk_ticket_links_state CHECK (state IN ('active', 'deleted', 'unlinked')),
    CONSTRAINT chk_ticket_links_source CHECK (source IN ('platform', 'person', 'migration')),
    CONSTRAINT chk_ticket_links_key CHECK (external_key ~ '^[A-Z][A-Z0-9_]*-[0-9]+$')
);

COMMENT ON TABLE ticket_links IS
    'Links between a finding or a remediation task and a tracker issue, with the owning integration.';

-- One active link per object and issue.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_links_finding_issue
    ON ticket_links (tenant_id, finding_id, integration_id, external_key)
    WHERE finding_id IS NOT NULL AND state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_links_campaign_issue
    ON ticket_links (tenant_id, campaign_id, integration_id, external_key)
    WHERE campaign_id IS NOT NULL AND state = 'active';
-- Inbound lookup: an issue of an integration → its objects.
CREATE INDEX IF NOT EXISTS idx_ticket_links_issue
    ON ticket_links (tenant_id, integration_id, external_key) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_ticket_links_finding
    ON ticket_links (finding_id, tenant_id) WHERE finding_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_links_campaign
    ON ticket_links (campaign_id, tenant_id) WHERE campaign_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ticket_links_tenant_integration
    ON ticket_links (tenant_id, integration_id);
CREATE INDEX IF NOT EXISTS idx_ticket_links_created_by
    ON ticket_links (created_by) WHERE created_by IS NOT NULL;

-- Backfill from the URL strings: a browse URL on the site of one of the
-- tenant's Jira integrations (the oldest such integration when several share
-- a site).
INSERT INTO ticket_links (tenant_id, integration_id, finding_id, external_key, project_key, url, source)
SELECT DISTINCT ON (f.tenant_id, f.id, u.key)
       f.tenant_id, i.id, f.id, u.key, split_part(u.key, '-', 1), u.uri, 'migration'
FROM findings f
CROSS JOIN LATERAL (
    SELECT uri, substring(uri FROM '/browse/([A-Z][A-Z0-9_]*-[0-9]+)/?$') AS key
    FROM unnest(f.work_item_uris) AS uri
) u
JOIN integrations i ON i.tenant_id = f.tenant_id AND i.provider = 'jira'
    AND COALESCE(i.base_url, '') <> ''
    AND u.uri LIKE rtrim(i.base_url, '/') || '/browse/%'
WHERE u.key IS NOT NULL
ORDER BY f.tenant_id, f.id, u.key, i.created_at
ON CONFLICT DO NOTHING;

INSERT INTO ticket_links (tenant_id, integration_id, campaign_id, external_key, project_key, url, role, source)
SELECT DISTINCT ON (t.tenant_id, t.campaign_id, t.issue_key)
       t.tenant_id, i.id, t.campaign_id, t.issue_key, split_part(t.issue_key, '-', 1), t.issue_url, 'epic', 'migration'
FROM remediation_campaign_tickets t
JOIN integrations i ON i.tenant_id = t.tenant_id AND i.provider = 'jira'
    AND COALESCE(i.base_url, '') <> ''
    AND t.issue_url LIKE rtrim(i.base_url, '/') || '/browse/%'
WHERE t.provider = 'jira' AND t.issue_key ~ '^[A-Z][A-Z0-9_]*-[0-9]+$'
ORDER BY t.tenant_id, t.campaign_id, t.issue_key, i.created_at
ON CONFLICT DO NOTHING;

-- Policy in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS ticket_links_tenant_isolation ON ticket_links;
CREATE POLICY ticket_links_tenant_isolation ON ticket_links
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
