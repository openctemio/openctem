-- Recreates scan_sessions empty, as the baseline (001146) defined it. Its
-- rows are not restored (they are in the pre-upgrade backup).
CREATE TABLE IF NOT EXISTS public.scan_sessions (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    sensor_id uuid,
    scanner_name character varying(100) NOT NULL,
    scanner_version character varying(50),
    scanner_type character varying(50),
    asset_type character varying(50) NOT NULL,
    asset_value character varying(500) NOT NULL,
    asset_id uuid,
    commit_sha character varying(40),
    branch character varying(200),
    base_commit_sha character varying(40),
    status character varying(20) DEFAULT 'pending'::character varying,
    error_message text,
    findings_total integer DEFAULT 0,
    findings_new integer DEFAULT 0,
    findings_fixed integer DEFAULT 0,
    findings_by_severity jsonb DEFAULT '{}'::jsonb,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms bigint,
    scan_profile_id uuid,
    quality_gate_result jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_scan_sessions_scanner_type CHECK (((scanner_type IS NULL) OR ((scanner_type)::text = ANY ((ARRAY['sast'::character varying, 'sca'::character varying, 'secret'::character varying, 'container'::character varying, 'iac'::character varying, 'dast'::character varying, 'recon'::character varying])::text[])))),
    CONSTRAINT chk_scan_sessions_status CHECK (((status)::text = ANY ((ARRAY['queued'::character varying, 'pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'canceled'::character varying, 'timeout'::character varying])::text[])))
);

COMMENT ON TABLE public.scan_sessions IS 'Individual scan execution records';

ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT scan_sessions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT fk_scan_sessions_tenant_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES public.assets(tenant_id, id) ON DELETE SET NULL (asset_id);
ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT scan_sessions_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT scan_sessions_scan_profile_id_fkey FOREIGN KEY (scan_profile_id) REFERENCES public.scan_profiles(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT scan_sessions_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.scan_sessions
    ADD CONSTRAINT scan_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_scan_sessions_asset ON public.scan_sessions USING btree (asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_asset_value ON public.scan_sessions USING btree (tenant_id, asset_type, asset_value);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_baseline ON public.scan_sessions USING btree (tenant_id, asset_type, asset_value, branch, status, completed_at DESC) WHERE ((status)::text = 'completed'::text);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_created ON public.scan_sessions USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_scanner ON public.scan_sessions USING btree (scanner_name);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_sensor ON public.scan_sessions USING btree (sensor_id);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON public.scan_sessions USING btree (status);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_tenant_created ON public.scan_sessions USING btree (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_tenant_status ON public.scan_sessions USING btree (tenant_id, status);

CREATE TRIGGER trigger_scan_sessions_updated_at BEFORE UPDATE ON public.scan_sessions FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE POLICY scan_sessions_tenant_isolation ON public.scan_sessions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
