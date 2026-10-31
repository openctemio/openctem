-- Web page monitoring (docs/rfcs/RFC-137-web-page-monitoring.md).
-- A watch is one URL of an organization's web origin (an http_service
-- asset). Snapshots keep the normalized form of a fetch that changed
-- something (the last few per watch); changes keep the diff. Every row
-- carries its tenant and references its parent by (tenant_id, id), so no row
-- can point into another tenant.
CREATE TABLE web_watches (
    id                 UUID          NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          UUID          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id           UUID          NOT NULL,
    parent_id          UUID,
    url                VARCHAR(2048) NOT NULL,
    mode               VARCHAR(8)    NOT NULL DEFAULT 'js',
    source             VARCHAR(10)   NOT NULL DEFAULT 'manual',
    enabled            BOOLEAN       NOT NULL DEFAULT true,
    cadence_hours      INTEGER       NOT NULL DEFAULT 24,
    ignore_patterns    TEXT[]        NOT NULL DEFAULT '{}',
    dynamic            BOOLEAN       NOT NULL DEFAULT false,
    change_streak      SMALLINT      NOT NULL DEFAULT 0,
    state              VARCHAR(10)   NOT NULL DEFAULT 'pending',
    last_error         VARCHAR(300),
    next_due_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    last_dispatched_at TIMESTAMPTZ,
    last_run_id        UUID,
    last_fetched_at    TIMESTAMPTZ,
    last_status        SMALLINT,
    last_changed_at    TIMESTAMPTZ,
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT pk_web_watches PRIMARY KEY (id),
    CONSTRAINT uq_web_watches_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_web_watches_url UNIQUE (tenant_id, url),
    CONSTRAINT fk_web_watches_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_web_watches_parent FOREIGN KEY (tenant_id, parent_id)
        REFERENCES web_watches(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_watches_mode CHECK (mode IN ('js', 'full')),
    CONSTRAINT chk_web_watches_source CHECK (source IN ('manual', 'suggested', 'derived')),
    CONSTRAINT chk_web_watches_state CHECK (state IN ('pending', 'ok', 'failed', 'blocked', 'waiting')),
    CONSTRAINT chk_web_watches_cadence CHECK (cadence_hours BETWEEN 6 AND 168),
    CONSTRAINT chk_web_watches_patterns CHECK (cardinality(ignore_patterns) <= 10)
);
CREATE INDEX idx_web_watches_due ON web_watches (next_due_at) WHERE enabled;
CREATE INDEX idx_web_watches_asset ON web_watches (tenant_id, asset_id);
CREATE INDEX idx_web_watches_parent ON web_watches (tenant_id, parent_id) WHERE parent_id IS NOT NULL;
COMMENT ON TABLE web_watches IS 'RFC-137: monitored URLs of an organization''s web origins';

CREATE TABLE web_snapshots (
    id           UUID          NOT NULL DEFAULT gen_random_uuid(),
    tenant_id    UUID          NOT NULL,
    watch_id     UUID          NOT NULL,
    fetched_at   TIMESTAMPTZ   NOT NULL,
    status_code  SMALLINT,
    content_type VARCHAR(100),
    final_url    VARCHAR(2048),
    size         BIGINT        NOT NULL DEFAULT 0,
    body_sha256  CHAR(64),
    content_hash CHAR(64)      NOT NULL,
    kind         VARCHAR(8)    NOT NULL,
    partial      BOOLEAN       NOT NULL DEFAULT false,
    scripts      JSONB         NOT NULL DEFAULT '[]',
    urls         JSONB         NOT NULL DEFAULT '[]',
    text_lines   JSONB         NOT NULL DEFAULT '[]',
    tool         VARCHAR(64),
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT pk_web_snapshots PRIMARY KEY (id),
    CONSTRAINT fk_web_snapshots_watch FOREIGN KEY (tenant_id, watch_id)
        REFERENCES web_watches(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_snapshots_kind CHECK (kind IN ('html', 'script', 'other'))
);
CREATE INDEX idx_web_snapshots_watch ON web_snapshots (tenant_id, watch_id, fetched_at DESC);
COMMENT ON TABLE web_snapshots IS 'RFC-137: normalized fetches that changed something (last 5 per watch)';

CREATE TABLE web_changes (
    id               UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    watch_id         UUID        NOT NULL,
    asset_id         UUID        NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL,
    severity         VARCHAR(8)  NOT NULL,
    muted            BOOLEAN     NOT NULL DEFAULT false,
    summary          JSONB       NOT NULL DEFAULT '{}',
    diff             JSONB       NOT NULL DEFAULT '{}',
    from_snapshot_id UUID,
    to_snapshot_id   UUID,
    CONSTRAINT pk_web_changes PRIMARY KEY (id),
    CONSTRAINT fk_web_changes_watch FOREIGN KEY (tenant_id, watch_id)
        REFERENCES web_watches(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_web_changes_severity CHECK (severity IN ('info', 'low', 'medium', 'high'))
);
CREATE INDEX idx_web_changes_tenant ON web_changes (tenant_id, detected_at DESC);
CREATE INDEX idx_web_changes_watch ON web_changes (tenant_id, watch_id, detected_at DESC);
CREATE INDEX idx_web_changes_retention ON web_changes (detected_at);
COMMENT ON TABLE web_changes IS 'RFC-137: detected changes of watched URLs with their diff (kept 180 days)';

-- The exposure type. The list keeps every type the platform knows today.
-- NOT VALID + VALIDATE keeps writes going on a large table.
ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_type;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (event_type IN (
    'port_open', 'port_closed', 'service_detected', 'service_changed', 'subdomain_discovered', 'subdomain_removed',
    'certificate_expiring', 'certificate_expired', 'bucket_public', 'bucket_private', 'repo_public', 'repo_private',
    'api_exposed', 'api_removed', 'credential_leaked', 'sensitive_data_exposed', 'misconfiguration', 'dns_change',
    'ssl_issue', 'header_missing', 'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
    'dangling_cname', 'dangling_ns', 'email_security_weak', 'subdomain_takeover', 'lookalike_domain',
    'web_interface_exposed', 'mcp_server_exposed', 'mail_server_blocklisted', 'third_party_script_added',
    'custom')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_type;
