-- Web evidence of an asset: what a sensor saw when it fetched it (final URL,
-- status, title, a short masked response snippet) and, when the organization
-- turned screenshots on, a screenshot kept in the tenant's file storage
-- (docs/rfcs/RFC-081-web-evidence-screenshots.md). Screenshots expire after
-- 30 days, the rest after 365 days.
CREATE TABLE asset_web_evidence (
    id                  UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID         NOT NULL,
    asset_id            UUID         NOT NULL,
    url                 VARCHAR(2048) NOT NULL,
    final_url           VARCHAR(2048) NOT NULL DEFAULT '',
    status_code         INTEGER      NOT NULL DEFAULT 0,
    title               VARCHAR(300) NOT NULL DEFAULT '',
    server              VARCHAR(200) NOT NULL DEFAULT '',
    content_type        VARCHAR(100) NOT NULL DEFAULT '',
    snippet             TEXT         NOT NULL DEFAULT '',
    snippet_truncated   BOOLEAN      NOT NULL DEFAULT false,
    tool                VARCHAR(100) NOT NULL DEFAULT '',
    screenshot_key      VARCHAR(500),
    screenshot_provider VARCHAR(20),
    screenshot_sha256   CHAR(64),
    screenshot_size     INTEGER,
    screenshot_width    INTEGER,
    screenshot_height   INTEGER,
    screenshot_expires_at TIMESTAMPTZ,
    captured_at         TIMESTAMPTZ  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_web_evidence PRIMARY KEY (id),
    CONSTRAINT fk_asset_web_evidence_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_web_evidence_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_web_evidence_snippet CHECK (octet_length(snippet) <= 8192),
    CONSTRAINT chk_asset_web_evidence_status CHECK (status_code = 0 OR status_code BETWEEN 100 AND 599),
    CONSTRAINT chk_asset_web_evidence_screenshot CHECK (
        (screenshot_key IS NULL AND screenshot_sha256 IS NULL)
        OR (screenshot_key IS NOT NULL AND screenshot_sha256 IS NOT NULL AND screenshot_size BETWEEN 1 AND 16777216))
);
COMMENT ON TABLE asset_web_evidence IS
    'RFC-081: what a sensor saw when it fetched a web asset; screenshots in tenant file storage, 30-day retention';

CREATE INDEX idx_asset_web_evidence_asset ON asset_web_evidence (tenant_id, asset_id, captured_at DESC);
CREATE INDEX idx_asset_web_evidence_screenshot_expiry ON asset_web_evidence (screenshot_expires_at)
    WHERE screenshot_key IS NOT NULL;
CREATE INDEX idx_asset_web_evidence_captured ON asset_web_evidence (captured_at);

-- A screenshot whose row goes away with its asset (cascade) is queued here so
-- the retention job deletes the file too; no stored image outlives its row.
CREATE TABLE asset_web_evidence_orphans (
    tenant_id  UUID         NOT NULL,
    provider   VARCHAR(20)  NOT NULL DEFAULT '',
    storage_key VARCHAR(500) NOT NULL,
    queued_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_web_evidence_orphans PRIMARY KEY (tenant_id, storage_key)
);

CREATE FUNCTION asset_web_evidence_queue_orphan() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.screenshot_key IS NOT NULL THEN
        INSERT INTO asset_web_evidence_orphans (tenant_id, provider, storage_key)
        VALUES (OLD.tenant_id, COALESCE(OLD.screenshot_provider, ''), OLD.screenshot_key)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_asset_web_evidence_orphan
    AFTER DELETE ON asset_web_evidence
    FOR EACH ROW EXECUTE FUNCTION asset_web_evidence_queue_orphan();
