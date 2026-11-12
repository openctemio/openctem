-- Reverts 003403_content_sources: template_sources comes back with the
-- organizations' git sources (without credentials, snapshots or platform
-- sources); the content packs snapshots used stay in the pack store.

DELETE FROM role_permissions WHERE permission_id = 'scans:sources:approve';
DELETE FROM permissions WHERE id = 'scans:sources:approve';

UPDATE modules SET name = 'Template Sources',
                   description = 'Upstream git sources that templates are synced from'
 WHERE id = 'template_sources';

CREATE TABLE template_sources (
    id uuid DEFAULT uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name character varying(255) NOT NULL,
    description text,
    source_type character varying(20) NOT NULL,
    template_type character varying(20) NOT NULL,
    git_config jsonb,
    s3_config jsonb,
    http_config jsonb,
    enabled boolean DEFAULT true NOT NULL,
    auto_sync_on_scan boolean DEFAULT true NOT NULL,
    cache_ttl_minutes integer DEFAULT 60 NOT NULL,
    last_sync_at timestamp with time zone,
    last_sync_hash character varying(64),
    last_sync_status character varying(20) DEFAULT 'pending'::character varying,
    last_sync_error text,
    total_templates integer DEFAULT 0 NOT NULL,
    last_sync_count integer DEFAULT 0 NOT NULL,
    credential_id uuid,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_sync_status CHECK (last_sync_status IN ('pending', 'in_progress', 'success', 'failed')),
    CONSTRAINT chk_template_source_type CHECK (source_type IN ('git', 's3', 'http')),
    CONSTRAINT chk_template_type CHECK (template_type IN ('nuclei', 'semgrep', 'betterleaks', 'gitleaks')),
    CONSTRAINT unique_template_source_name UNIQUE (tenant_id, name)
);
COMMENT ON TABLE template_sources IS 'External sources for scanner templates (Git, S3, HTTP)';
CREATE INDEX idx_template_sources_enabled ON template_sources USING btree (enabled) WHERE (enabled = true);
CREATE INDEX idx_template_sources_needs_sync ON template_sources USING btree (tenant_id, last_sync_at) WHERE ((enabled = true) AND (auto_sync_on_scan = true));
CREATE INDEX idx_template_sources_template_type ON template_sources USING btree (template_type);
CREATE INDEX idx_template_sources_type ON template_sources USING btree (source_type);
CREATE TRIGGER update_template_sources_updated_at BEFORE UPDATE ON template_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE POLICY template_sources_tenant_isolation ON template_sources
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));

INSERT INTO template_sources (id, tenant_id, name, description, source_type, template_type, git_config,
                              enabled, created_by, created_at, updated_at)
SELECT cs.id, cs.tenant_id, left(cs.name, 255), cs.description, 'git',
       CASE cs.kind WHEN 'nuclei-templates' THEN 'nuclei' ELSE 'semgrep' END,
       jsonb_build_object('url', cs.url, 'branch', cs.ref, 'path', cs.path, 'auth_type', 'none'),
       cs.enabled, cs.created_by, cs.created_at, cs.updated_at
FROM content_sources cs
WHERE cs.scope = 'tenant' AND cs.origin = 'git' AND cs.kind IN ('nuclei-templates', 'semgrep-rules')
ON CONFLICT (tenant_id, name) DO NOTHING;

ALTER TABLE scanner_templates
    ADD CONSTRAINT scanner_templates_source_id_fkey FOREIGN KEY (source_id) REFERENCES template_sources(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scanner_templates_source ON scanner_templates USING btree (source_id) WHERE (source_id IS NOT NULL);

ALTER TABLE content_sources DROP CONSTRAINT IF EXISTS fk_content_sources_current;
ALTER TABLE content_sources DROP CONSTRAINT IF EXISTS fk_content_sources_previous;
DROP TABLE IF EXISTS content_source_snapshots;
DROP TABLE IF EXISTS content_sources;
DROP FUNCTION IF EXISTS content_sources_keep_rule_namespace();
