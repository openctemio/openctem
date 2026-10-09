-- Recreates the two tables (empty) as they were before 001482.

CREATE TABLE public.component_licenses (
    component_id uuid NOT NULL,
    license_id character varying(100) NOT NULL
);

COMMENT ON TABLE public.component_licenses IS 'Links global components to their licenses';

CREATE TABLE public.tool_executions (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    tool_id uuid NOT NULL,
    sensor_id uuid,
    scan_run_id uuid,
    scan_run_step_id uuid,
    status character varying(20) DEFAULT 'running'::character varying NOT NULL,
    input_config jsonb DEFAULT '{}'::jsonb,
    targets_count integer DEFAULT 0,
    findings_count integer DEFAULT 0,
    output_summary jsonb DEFAULT '{}'::jsonb,
    error_message text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    duration_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tool_executions_status CHECK (((status)::text = ANY (ARRAY[('pending'::character varying)::text, ('running'::character varying)::text, ('completed'::character varying)::text, ('failed'::character varying)::text, ('timeout'::character varying)::text, ('canceled'::character varying)::text])))
);

COMMENT ON TABLE public.tool_executions IS 'Tool execution history for analytics and debugging';

ALTER TABLE ONLY public.component_licenses
    ADD CONSTRAINT pk_component_licenses PRIMARY KEY (component_id, license_id);

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_pkey PRIMARY KEY (id);

CREATE INDEX idx_component_licenses_license ON public.component_licenses USING btree (license_id);

CREATE INDEX idx_tool_executions_completed ON public.tool_executions USING btree (completed_at DESC) WHERE ((status)::text = 'completed'::text);

CREATE INDEX idx_tool_executions_scan_run ON public.tool_executions USING btree (scan_run_id) WHERE (scan_run_id IS NOT NULL);

CREATE INDEX idx_tool_executions_sensor ON public.tool_executions USING btree (sensor_id) WHERE (sensor_id IS NOT NULL);

CREATE INDEX idx_tool_executions_started ON public.tool_executions USING btree (started_at DESC);

CREATE INDEX idx_tool_executions_status ON public.tool_executions USING btree (status);

CREATE INDEX idx_tool_executions_step ON public.tool_executions USING btree (scan_run_step_id) WHERE (scan_run_step_id IS NOT NULL);

CREATE INDEX idx_tool_executions_tenant_tool ON public.tool_executions USING btree (tenant_id, tool_id);

CREATE INDEX idx_tool_executions_tool ON public.tool_executions USING btree (tool_id);

ALTER TABLE ONLY public.component_licenses
    ADD CONSTRAINT component_licenses_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.components(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.component_licenses
    ADD CONSTRAINT component_licenses_license_id_fkey FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_scan_run_id_fkey FOREIGN KEY (scan_run_id) REFERENCES public.scan_runs(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_scan_run_step_id_fkey FOREIGN KEY (scan_run_step_id) REFERENCES public.scan_run_steps(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_sensor_id_fkey FOREIGN KEY (sensor_id) REFERENCES public.sensors(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.tool_executions
    ADD CONSTRAINT tool_executions_tool_id_fkey FOREIGN KEY (tool_id) REFERENCES public.tools(id) ON DELETE CASCADE;

CREATE POLICY tool_executions_tenant_isolation ON public.tool_executions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
