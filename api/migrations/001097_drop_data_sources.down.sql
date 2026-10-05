-- Recreate data_sources (empty), its enum, assets.source_id / source_ref and
-- the foreign keys that pointed at it. The removed 'asset_source' settings key
-- held no configuration and is not restored.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'source_status') THEN
        CREATE TYPE source_status AS ENUM ('pending', 'active', 'inactive', 'error', 'disabled');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS data_sources (
    id uuid DEFAULT uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    type source_type DEFAULT 'manual'::source_type NOT NULL,
    description text,
    version character varying(50),
    hostname character varying(255),
    ip_address inet,
    api_key_hash character varying(255),
    api_key_prefix character varying(12),
    api_key_last_used_at timestamp with time zone,
    status source_status DEFAULT 'pending'::source_status NOT NULL,
    last_seen_at timestamp with time zone,
    last_error text,
    error_count integer DEFAULT 0,
    capabilities jsonb DEFAULT '[]'::jsonb,
    config jsonb DEFAULT '{}'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    assets_collected bigint DEFAULT 0,
    findings_reported bigint DEFAULT 0,
    last_sync_at timestamp with time zone,
    last_sync_duration_ms integer,
    last_sync_assets_count integer,
    last_sync_findings_count integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT data_sources_pkey PRIMARY KEY (id),
    CONSTRAINT data_sources_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT data_sources_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

COMMENT ON TABLE data_sources IS 'Registry of data collectors, scanners, and integrations';

CREATE INDEX IF NOT EXISTS idx_data_sources_api_key_prefix ON data_sources USING btree (api_key_prefix) WHERE (api_key_prefix IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_data_sources_last_seen ON data_sources USING btree (last_seen_at) WHERE (status = 'active'::source_status);
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant ON data_sources USING btree (tenant_id);
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant_status ON data_sources USING btree (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant_type ON data_sources USING btree (tenant_id, type);

DROP TRIGGER IF EXISTS trigger_data_sources_updated_at ON data_sources;
CREATE TRIGGER trigger_data_sources_updated_at BEFORE UPDATE ON data_sources FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP POLICY IF EXISTS data_sources_tenant_isolation ON data_sources;
CREATE POLICY data_sources_tenant_isolation ON data_sources USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS source_id uuid,
    ADD COLUMN IF NOT EXISTS source_ref character varying(255);
CREATE INDEX IF NOT EXISTS idx_assets_source_id ON assets USING btree (source_id) WHERE (source_id IS NOT NULL);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_source_id_fkey') THEN
        ALTER TABLE assets ADD CONSTRAINT assets_source_id_fkey
            FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE SET NULL;
    END IF;
    IF to_regclass('public.asset_sources') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'asset_sources_source_id_fkey') THEN
        ALTER TABLE asset_sources ADD CONSTRAINT asset_sources_source_id_fkey
            FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE SET NULL;
    END IF;
    IF to_regclass('public.finding_data_sources') IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'finding_data_sources_source_id_fkey') THEN
        ALTER TABLE finding_data_sources ADD CONSTRAINT finding_data_sources_source_id_fkey
            FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE SET NULL;
    END IF;
END
$$;
