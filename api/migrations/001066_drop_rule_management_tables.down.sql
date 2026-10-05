-- Recreate the tables dropped by 001060, as they were (empty).


CREATE TABLE public.finding_data_sources (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    finding_id uuid NOT NULL,
    source_type public.source_type NOT NULL,
    source_id uuid,
    first_seen_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    source_ref character varying(255),
    scan_id character varying(255),
    contributed_data jsonb DEFAULT '{}'::jsonb,
    confidence integer DEFAULT 100,
    is_primary boolean DEFAULT false,
    seen_count integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_finding_data_sources_confidence CHECK (((confidence >= 0) AND (confidence <= 100)))
);

COMMENT ON TABLE public.finding_data_sources IS 'Track which data sources discovered each finding';

CREATE TABLE public.rule_bundles (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    version character varying(50) NOT NULL,
    content_hash character varying(64) NOT NULL,
    rule_count integer DEFAULT 0 NOT NULL,
    source_count integer DEFAULT 0 NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    source_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    source_hashes jsonb DEFAULT '{}'::jsonb NOT NULL,
    storage_path character varying(500) NOT NULL,
    status character varying(20) DEFAULT 'building'::character varying NOT NULL,
    build_error text,
    build_started_at timestamp with time zone,
    build_completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT chk_rule_bundles_status CHECK (((status)::text = ANY (ARRAY[('building'::character varying)::text, ('ready'::character varying)::text, ('failed'::character varying)::text, ('expired'::character varying)::text])))
);

COMMENT ON TABLE public.rule_bundles IS 'Pre-compiled rule packages for sensor download';

CREATE TABLE public.rule_overrides (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    tool_id uuid,
    rule_pattern character varying(500) NOT NULL,
    is_pattern boolean DEFAULT false NOT NULL,
    enabled boolean NOT NULL,
    severity_override character varying(20),
    asset_group_id uuid,
    scan_profile_id uuid,
    reason text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT chk_rule_overrides_severity CHECK (((severity_override)::text = ANY (ARRAY[('critical'::character varying)::text, ('high'::character varying)::text, ('medium'::character varying)::text, ('low'::character varying)::text, ('info'::character varying)::text])))
);

COMMENT ON TABLE public.rule_overrides IS 'Tenant-specific rule enable/disable configuration';

CREATE TABLE public.rule_sources (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    tool_id uuid,
    name character varying(255) NOT NULL,
    description text,
    source_type character varying(20) NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    credentials_id uuid,
    sync_enabled boolean DEFAULT true NOT NULL,
    sync_interval_minutes integer DEFAULT 60 NOT NULL,
    last_sync_at timestamp with time zone,
    last_sync_status character varying(20) DEFAULT 'pending'::character varying,
    last_sync_error text,
    last_sync_duration_ms integer,
    content_hash character varying(64),
    rule_count integer DEFAULT 0,
    priority integer DEFAULT 100 NOT NULL,
    is_platform_default boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_rule_sources_sync_status CHECK (((last_sync_status)::text = ANY (ARRAY[('pending'::character varying)::text, ('syncing'::character varying)::text, ('success'::character varying)::text, ('failed'::character varying)::text]))),
    CONSTRAINT chk_rule_sources_type CHECK (((source_type)::text = ANY (ARRAY[('git'::character varying)::text, ('http'::character varying)::text, ('local'::character varying)::text])))
);

COMMENT ON TABLE public.rule_sources IS 'Sources for security rules (Git repos, HTTP URLs, etc.)';

CREATE TABLE public.rule_sync_history (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    source_id uuid NOT NULL,
    status character varying(20) NOT NULL,
    rules_added integer DEFAULT 0,
    rules_updated integer DEFAULT 0,
    rules_removed integer DEFAULT 0,
    duration_ms integer,
    error_message text,
    error_details jsonb,
    previous_hash character varying(64),
    new_hash character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_rule_sync_status CHECK (((status)::text = ANY (ARRAY[('started'::character varying)::text, ('success'::character varying)::text, ('failed'::character varying)::text])))
);

COMMENT ON TABLE public.rule_sync_history IS 'Audit trail of rule synchronization';

CREATE TABLE public.rules (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    source_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    tool_id uuid,
    rule_id character varying(500) NOT NULL,
    name character varying(500),
    severity character varying(20),
    category character varying(100),
    subcategory character varying(100),
    tags text[] DEFAULT '{}'::text[],
    description text,
    recommendation text,
    "references" text[] DEFAULT '{}'::text[],
    cwe_ids text[] DEFAULT '{}'::text[],
    owasp_ids text[] DEFAULT '{}'::text[],
    file_path character varying(500),
    content_hash character varying(64),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_rules_severity CHECK (((severity)::text = ANY (ARRAY[('critical'::character varying)::text, ('high'::character varying)::text, ('medium'::character varying)::text, ('low'::character varying)::text, ('info'::character varying)::text, ('unknown'::character varying)::text])))
);

COMMENT ON TABLE public.rules IS 'Individual rules indexed from sources for UI/filtering';

ALTER TABLE ONLY public.finding_data_sources
    ADD CONSTRAINT finding_data_sources_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.finding_data_sources
    ADD CONSTRAINT finding_data_sources_unique UNIQUE (finding_id, source_type, source_id);

ALTER TABLE ONLY public.rule_bundles
    ADD CONSTRAINT rule_bundles_content_hash_key UNIQUE (content_hash);

ALTER TABLE ONLY public.rule_bundles
    ADD CONSTRAINT rule_bundles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rule_sources
    ADD CONSTRAINT rule_sources_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rule_sync_history
    ADD CONSTRAINT rule_sync_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT unique_rule_override UNIQUE (tenant_id, tool_id, rule_pattern, asset_group_id, scan_profile_id);

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT unique_rule_source UNIQUE (source_id, rule_id);

CREATE INDEX idx_finding_data_sources_finding ON public.finding_data_sources USING btree (finding_id);

CREATE INDEX idx_finding_data_sources_last_seen ON public.finding_data_sources USING btree (last_seen_at);

CREATE INDEX idx_finding_data_sources_primary ON public.finding_data_sources USING btree (finding_id) WHERE (is_primary = true);

CREATE INDEX idx_finding_data_sources_scan_id ON public.finding_data_sources USING btree (scan_id) WHERE (scan_id IS NOT NULL);

CREATE INDEX idx_finding_data_sources_source ON public.finding_data_sources USING btree (source_id) WHERE (source_id IS NOT NULL);

CREATE INDEX idx_finding_data_sources_source_type ON public.finding_data_sources USING btree (source_type);

CREATE INDEX idx_rule_bundles_expires ON public.rule_bundles USING btree (expires_at) WHERE (expires_at IS NOT NULL);

CREATE INDEX idx_rule_bundles_latest ON public.rule_bundles USING btree (tenant_id, tool_id, created_at DESC) WHERE ((status)::text = 'ready'::text);

CREATE INDEX idx_rule_bundles_status ON public.rule_bundles USING btree (status);

CREATE INDEX idx_rule_bundles_tenant_tool ON public.rule_bundles USING btree (tenant_id, tool_id);

CREATE INDEX idx_rule_overrides_enabled ON public.rule_overrides USING btree (enabled);

CREATE INDEX idx_rule_overrides_expires ON public.rule_overrides USING btree (expires_at) WHERE (expires_at IS NOT NULL);

CREATE INDEX idx_rule_overrides_tenant ON public.rule_overrides USING btree (tenant_id);

CREATE INDEX idx_rule_overrides_tool ON public.rule_overrides USING btree (tool_id);

CREATE INDEX idx_rule_sources_enabled ON public.rule_sources USING btree (enabled);

CREATE INDEX idx_rule_sources_sync_status ON public.rule_sources USING btree (last_sync_status);

CREATE INDEX idx_rule_sources_tenant ON public.rule_sources USING btree (tenant_id);

CREATE UNIQUE INDEX idx_rule_sources_tenant_tool_name ON public.rule_sources USING btree (tenant_id, COALESCE(tool_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

CREATE INDEX idx_rule_sources_tool ON public.rule_sources USING btree (tool_id);

CREATE INDEX idx_rule_sync_history_created ON public.rule_sync_history USING btree (created_at);

CREATE INDEX idx_rule_sync_history_source ON public.rule_sync_history USING btree (source_id);

CREATE INDEX idx_rules_category ON public.rules USING btree (category);

CREATE INDEX idx_rules_rule_id ON public.rules USING btree (rule_id);

CREATE INDEX idx_rules_severity ON public.rules USING btree (severity);

CREATE INDEX idx_rules_source ON public.rules USING btree (source_id);

CREATE INDEX idx_rules_tags ON public.rules USING gin (tags);

CREATE INDEX idx_rules_tenant ON public.rules USING btree (tenant_id);

CREATE INDEX idx_rules_tool ON public.rules USING btree (tool_id);

CREATE TRIGGER trigger_finding_data_sources_updated_at BEFORE UPDATE ON public.finding_data_sources FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER trigger_rule_overrides_updated_at BEFORE UPDATE ON public.rule_overrides FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER trigger_rule_sources_updated_at BEFORE UPDATE ON public.rule_sources FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER trigger_rules_updated_at BEFORE UPDATE ON public.rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

ALTER TABLE ONLY public.finding_data_sources
    ADD CONSTRAINT finding_data_sources_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.finding_data_sources
    ADD CONSTRAINT finding_data_sources_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.data_sources(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.rule_bundles
    ADD CONSTRAINT rule_bundles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_bundles
    ADD CONSTRAINT rule_bundles_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.tools(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_asset_group_id_fkey FOREIGN KEY (asset_group_id) REFERENCES public.asset_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_scan_profile_id_fkey FOREIGN KEY (scan_profile_id) REFERENCES public.scan_profiles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_overrides
    ADD CONSTRAINT rule_overrides_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.tools(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_sources
    ADD CONSTRAINT rule_sources_credentials_id_fkey FOREIGN KEY (credentials_id) REFERENCES public.credentials(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.rule_sources
    ADD CONSTRAINT rule_sources_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rule_sources
    ADD CONSTRAINT rule_sources_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.tools(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.rule_sync_history
    ADD CONSTRAINT rule_sync_history_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.rule_sources(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.rule_sources(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.tools(id) ON DELETE SET NULL;

CREATE POLICY rule_bundles_tenant_isolation ON public.rule_bundles USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY rule_overrides_tenant_isolation ON public.rule_overrides USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY rule_sources_tenant_isolation ON public.rule_sources USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY rules_tenant_isolation ON public.rules USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

