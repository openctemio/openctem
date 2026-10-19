-- Emerging-threat alerts (docs/rfcs/RFC-117-emerging-threat-alerts.md): one
-- alert per organization and vulnerability, the assets it affects, the
-- planner's queue and per-organization delivery state. Every table carries
-- tenant_id; assets are referenced with the composite (tenant_id, asset_id)
-- key so an alert can never point at another organization's asset.

CREATE TABLE threat_alerts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vuln_id          TEXT NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 64),
    title            TEXT NOT NULL DEFAULT '' CHECK (length(title) <= 200),
    severity         TEXT NOT NULL DEFAULT '' CHECK (severity IN ('', 'none', 'low', 'medium', 'high', 'critical')),
    level            TEXT NOT NULL CHECK (level IN ('immediate', 'digest', 'listed')),
    tier             TEXT NOT NULL CHECK (tier IN ('confirmed', 'possible')),
    state            TEXT NOT NULL DEFAULT 'new'
                     CHECK (state IN ('new', 'acknowledged', 'remediating', 'not_affected', 'resolved')),
    state_reason     TEXT NOT NULL DEFAULT '' CHECK (length(state_reason) <= 64),
    state_note       TEXT NOT NULL DEFAULT '' CHECK (length(state_note) <= 500),
    state_changed_by UUID,
    state_changed_at TIMESTAMPTZ,
    suppressed_until TIMESTAMPTZ,
    ets              SMALLINT NOT NULL CHECK (ets BETWEEN 0 AND 100),
    ets_breakdown    JSONB NOT NULL DEFAULT '{}' CHECK (length(ets_breakdown::text) <= 1024),
    in_kev           BOOLEAN NOT NULL DEFAULT false,
    kev_ransomware   BOOLEAN NOT NULL DEFAULT false,
    epss             REAL,
    confirmed_assets INTEGER NOT NULL DEFAULT 0,
    possible_assets  INTEGER NOT NULL DEFAULT 0,
    internet_facing_assets INTEGER NOT NULL DEFAULT 0,
    last_event_kind  TEXT NOT NULL DEFAULT '' CHECK (length(last_event_kind) <= 32),
    source_at        TIMESTAMPTZ,
    event_at         TIMESTAMPTZ,
    notified_level   TEXT NOT NULL DEFAULT 'none' CHECK (notified_level IN ('none', 'digest', 'immediate')),
    notified_tier    TEXT NOT NULL DEFAULT '' CHECK (notified_tier IN ('', 'confirmed', 'possible')),
    notified_at      TIMESTAMPTZ,
    immediate_sent_at TIMESTAMPTZ,
    digest_pending   BOOLEAN NOT NULL DEFAULT false,
    held             BOOLEAN NOT NULL DEFAULT false,
    baseline         BOOLEAN NOT NULL DEFAULT false,
    planned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at  TIMESTAMPTZ,
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_threat_alerts_vuln UNIQUE (tenant_id, vuln_id),
    CONSTRAINT uq_threat_alerts_tenant_id UNIQUE (tenant_id, id)
);
CREATE INDEX idx_threat_alerts_list ON threat_alerts (tenant_id, state, ets DESC);
CREATE INDEX idx_threat_alerts_pending_immediate ON threat_alerts (tenant_id)
    WHERE level = 'immediate' AND notified_level <> 'immediate' AND state IN ('new', 'acknowledged', 'remediating');
CREATE INDEX idx_threat_alerts_digest ON threat_alerts (tenant_id) WHERE digest_pending;
CREATE INDEX idx_threat_alerts_vuln ON threat_alerts (vuln_id);
COMMENT ON TABLE threat_alerts IS
    'Emerging-threat alert (RFC-117): one per organization and vulnerability; the unit of attention above findings.';

CREATE TABLE threat_alert_assets (
    tenant_id       UUID NOT NULL,
    alert_id        UUID NOT NULL,
    asset_id        UUID NOT NULL,
    match_kind      TEXT NOT NULL CHECK (match_kind IN ('confirmed', 'likely', 'possible')),
    confidence      SMALLINT NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    internet_facing BOOLEAN NOT NULL DEFAULT false,
    criticality     TEXT NOT NULL DEFAULT '' CHECK (length(criticality) <= 32),
    product         TEXT NOT NULL DEFAULT '' CHECK (length(product) <= 200),
    version_seen    TEXT NOT NULL DEFAULT '' CHECK (length(version_seen) <= 64),
    finding_id      UUID,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (alert_id, asset_id),
    CONSTRAINT fk_threat_alert_assets_alert FOREIGN KEY (tenant_id, alert_id)
        REFERENCES threat_alerts (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_threat_alert_assets_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_threat_alert_assets_asset ON threat_alert_assets (tenant_id, asset_id);
COMMENT ON TABLE threat_alert_assets IS
    'Assets an emerging-threat alert affects (RFC-117): confirmed (open finding), likely (match below 80% confidence) or possible (product known, version unknown).';

-- Organizations and vulnerabilities waiting to be planned.
CREATE TABLE threat_alert_queue (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vuln_id   TEXT NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 64),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, vuln_id)
);

-- Per-organization delivery state.
CREATE TABLE threat_alert_tenant_state (
    tenant_id              UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    baseline_at            TIMESTAMPTZ,
    baseline_digest_due    BOOLEAN NOT NULL DEFAULT false,
    last_digest_on         DATE,
    last_digest_at         TIMESTAMPTZ,
    last_fold_at           TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The notification event catalog.
INSERT INTO event_types (id, name, description, category, module_id, is_active, metadata, created_at) VALUES
    ('emerging_threat', 'Emerging threat', 'A newly urgent vulnerability (new CVE, KEV addition, EPSS jump) affects your assets', 'finding', 'threat_intel', true, '{}', NOW()),
    ('emerging_threat_digest', 'Emerging threats daily digest', 'Daily summary of new and escalated emerging-threat alerts', 'finding', 'threat_intel', true, '{}', NOW())
ON CONFLICT (id) DO NOTHING;

-- Channels that receive new findings or priority escalations also receive
-- the alerts that announce matched findings and replace the per-finding
-- KEV escalations; the per-integration event list stays the switch.
UPDATE integration_notification_extensions
   SET enabled_event_types = enabled_event_types || '["emerging_threat", "emerging_threat_digest"]'::jsonb
 WHERE (enabled_event_types ? 'new_finding' OR enabled_event_types ? 'finding_priority_escalated')
   AND NOT enabled_event_types ? 'emerging_threat';
