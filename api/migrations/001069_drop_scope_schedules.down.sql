-- Recreate scan_schedules as it was (empty).


CREATE TABLE public.scan_schedules (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    scan_type character varying(50) NOT NULL,
    target_scope character varying(20) DEFAULT 'all'::character varying,
    target_ids uuid[] DEFAULT '{}'::uuid[],
    target_tags text[] DEFAULT '{}'::text[],
    scanner_configs jsonb DEFAULT '{}'::jsonb,
    schedule_type character varying(20) NOT NULL,
    cron_expression character varying(100),
    interval_hours integer,
    enabled boolean DEFAULT true,
    last_run_at timestamp with time zone,
    last_run_status character varying(20),
    next_run_at timestamp with time zone,
    notify_on_completion boolean DEFAULT true,
    notify_on_findings boolean DEFAULT true,
    notification_channels jsonb DEFAULT '["email"]'::jsonb,
    created_by character varying(200),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_scan_schedule_interval CHECK (((interval_hours >= 0) AND (interval_hours <= 8760))),
    CONSTRAINT chk_scan_schedule_target CHECK (((target_scope)::text = ANY (ARRAY[('all'::character varying)::text, ('selected'::character varying)::text, ('tag'::character varying)::text]))),
    CONSTRAINT chk_scan_schedule_timing CHECK (((schedule_type)::text = ANY (ARRAY[('cron'::character varying)::text, ('interval'::character varying)::text, ('manual'::character varying)::text]))),
    CONSTRAINT chk_scan_schedule_type CHECK (((scan_type)::text = ANY (ARRAY[('full'::character varying)::text, ('incremental'::character varying)::text, ('targeted'::character varying)::text, ('vulnerability'::character varying)::text, ('compliance'::character varying)::text, ('secret'::character varying)::text, ('sast'::character varying)::text, ('dast'::character varying)::text, ('sca'::character varying)::text])))
);

COMMENT ON TABLE public.scan_schedules IS 'Automated scan configurations with scheduling';

ALTER TABLE ONLY public.scan_schedules
    ADD CONSTRAINT scan_schedules_pkey PRIMARY KEY (id);

CREATE INDEX idx_scan_schedules_enabled ON public.scan_schedules USING btree (tenant_id, enabled) WHERE (enabled = true);

CREATE INDEX idx_scan_schedules_next_run ON public.scan_schedules USING btree (next_run_at) WHERE (enabled = true);

CREATE INDEX idx_scan_schedules_tenant ON public.scan_schedules USING btree (tenant_id);

CREATE TRIGGER trigger_scan_schedules_updated_at BEFORE UPDATE ON public.scan_schedules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

ALTER TABLE ONLY public.scan_schedules
    ADD CONSTRAINT scan_schedules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

CREATE POLICY scan_schedules_tenant_isolation ON public.scan_schedules USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

