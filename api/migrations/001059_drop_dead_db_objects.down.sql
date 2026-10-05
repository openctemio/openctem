-- Recreate the objects dropped by 001056, exactly as they were (DDL taken
-- from the schema at 001055). The tables come back empty: they were empty.

-- Functions
CREATE OR REPLACE FUNCTION public.can_tool_scan_asset_type(p_target_types text[], p_asset_type text)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE
AS $function$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM target_asset_type_mappings
        WHERE target_type = ANY(p_target_types)
          AND asset_type = p_asset_type
          AND is_active = TRUE
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION public.cleanup_old_audit_logs(retention_days integer DEFAULT 365)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs
    WHERE logged_at < NOW() - (retention_days || ' days')::INTERVAL
      AND severity NOT IN ('high', 'critical');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.expire_scope_exclusions()
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    UPDATE scope_exclusions
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'active'
      AND expires_at IS NOT NULL
      AND expires_at < NOW();
END;
$function$
;

CREATE OR REPLACE FUNCTION public.expire_suppression_rules()
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    UPDATE suppression_rules
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'approved'
      AND expires_at IS NOT NULL
      AND expires_at < NOW();
END;
$function$
;

CREATE OR REPLACE FUNCTION public.get_compatible_asset_types(p_target_types text[])
 RETURNS TABLE(asset_type text)
 LANGUAGE plpgsql
 STABLE
AS $function$
BEGIN
    RETURN QUERY
    SELECT DISTINCT m.asset_type::TEXT
    FROM target_asset_type_mappings m
    WHERE m.target_type = ANY(p_target_types)
      AND m.is_active = TRUE
    ORDER BY m.asset_type;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.get_user_permissions(p_tenant_id uuid, p_user_id uuid)
 RETURNS TABLE(permission_id character varying)
 LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN QUERY
    SELECT DISTINCT rp.permission_id
    FROM user_roles ur
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE ur.tenant_id = p_tenant_id
      AND ur.user_id = p_user_id;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.refresh_access_for_direct_owner_add(p_asset_id uuid, p_user_id uuid, p_ownership_type character varying)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.refresh_access_for_direct_owner_remove(p_asset_id uuid, p_user_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM refresh_access_for_grant_remove(p_asset_id, p_user_id);
END;
$function$
;

CREATE OR REPLACE FUNCTION public.user_has_full_data_access(p_tenant_id uuid, p_user_id uuid)
 RETURNS boolean
 LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.tenant_id = p_tenant_id
          AND ur.user_id = p_user_id
          AND r.has_full_data_access = TRUE
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION public.user_has_permission(p_tenant_id uuid, p_user_id uuid, p_permission character varying)
 RETURNS boolean
 LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.tenant_id = p_tenant_id
          AND ur.user_id = p_user_id
          AND rp.permission_id = p_permission
    );
END;
$function$
;

COMMENT ON FUNCTION public.can_tool_scan_asset_type(p_target_types text[], p_asset_type text) IS 'Returns TRUE if any of the given target types can scan the specified asset type';
COMMENT ON FUNCTION public.cleanup_old_audit_logs(retention_days integer) IS 'Deletes audit logs older than retention period (preserves high/critical severity)';
COMMENT ON FUNCTION public.expire_scope_exclusions() IS 'Marks expired scope exclusions as expired';
COMMENT ON FUNCTION public.expire_suppression_rules() IS 'Marks expired suppression rules as expired';
COMMENT ON FUNCTION public.get_compatible_asset_types(p_target_types text[]) IS 'Returns all asset types that can be scanned by any of the given target types';

-- deprecated schema (000213)

CREATE SCHEMA deprecated;

COMMENT ON SCHEMA deprecated IS 'Quarantined tables pending removal (migration 000213). Kept temporarily for a safe, reversible retirement; a later migration DROPs them once confirmed unused.';

CREATE TABLE deprecated.agent_audit_logs (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    agent_id uuid,
    api_key_id uuid,
    event_type character varying(50) NOT NULL,
    event_action character varying(100) NOT NULL,
    event_status character varying(20) NOT NULL,
    ip_address inet,
    user_agent character varying(500),
    request_id character varying(100),
    details jsonb DEFAULT '{}'::jsonb,
    error_message text,
    duration_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_agent_audit_logs_status CHECK (((event_status)::text = ANY (ARRAY[('success'::character varying)::text, ('failure'::character varying)::text, ('denied'::character varying)::text])))
);

COMMENT ON TABLE deprecated.agent_audit_logs IS 'Audit log for agent activities';

CREATE TABLE deprecated.agent_metrics (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    agent_id uuid NOT NULL,
    metric_type character varying(50) NOT NULL,
    metric_value numeric(12,4) NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE deprecated.agent_metrics IS 'Agent performance metrics';

CREATE TABLE deprecated.email_logs (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid,
    user_id uuid,
    email_type character varying(100) NOT NULL,
    recipient_email character varying(255) NOT NULL,
    subject character varying(500),
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    task_id character varying(255),
    queue_name character varying(100),
    retry_count integer DEFAULT 0,
    max_retries integer DEFAULT 3,
    last_error text,
    related_entity_type character varying(100),
    related_entity_id uuid,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    queued_at timestamp with time zone,
    sent_at timestamp with time zone,
    failed_at timestamp with time zone,
    CONSTRAINT chk_email_logs_status CHECK (((status)::text = ANY (ARRAY[('pending'::character varying)::text, ('queued'::character varying)::text, ('processing'::character varying)::text, ('sent'::character varying)::text, ('failed'::character varying)::text, ('bounced'::character varying)::text])))
);

COMMENT ON TABLE deprecated.email_logs IS 'Email delivery tracking';

CREATE TABLE deprecated.finding_regression_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    previous_resolution character varying(50),
    reopened_by uuid,
    reason text,
    detected_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE deprecated.registration_tokens (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    token_hash character varying(64) NOT NULL,
    token_prefix character varying(12) NOT NULL,
    agent_type character varying(50) DEFAULT 'agent'::character varying,
    agent_name_prefix character varying(100),
    default_scopes text[] DEFAULT '{}'::text[],
    default_capabilities text[] DEFAULT '{}'::text[],
    default_tools text[] DEFAULT '{}'::text[],
    default_labels jsonb DEFAULT '{}'::jsonb,
    max_uses integer DEFAULT 1,
    uses_count integer DEFAULT 0,
    expires_at timestamp with time zone,
    is_active boolean DEFAULT true,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE deprecated.registration_tokens IS 'Tokens for automatic agent registration';

CREATE TABLE deprecated.scan_profile_template_sources (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    scan_profile_id uuid NOT NULL,
    source_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE deprecated.scan_profile_template_sources IS 'Links scan profiles to template sources';

CREATE TABLE deprecated.threat_actor_cves (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    threat_actor_id uuid NOT NULL,
    cve_id character varying(30) NOT NULL,
    confidence character varying(20) DEFAULT 'medium'::character varying,
    source character varying(100),
    first_observed date,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY deprecated.agent_audit_logs
    ADD CONSTRAINT agent_audit_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.agent_metrics
    ADD CONSTRAINT agent_metrics_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.email_logs
    ADD CONSTRAINT email_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.finding_regression_events
    ADD CONSTRAINT finding_regression_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.registration_tokens
    ADD CONSTRAINT registration_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.scan_profile_template_sources
    ADD CONSTRAINT scan_profile_template_sources_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.threat_actor_cves
    ADD CONSTRAINT threat_actor_cves_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deprecated.threat_actor_cves
    ADD CONSTRAINT threat_actor_cves_tenant_id_threat_actor_id_cve_id_key UNIQUE (tenant_id, threat_actor_id, cve_id);

ALTER TABLE ONLY deprecated.scan_profile_template_sources
    ADD CONSTRAINT unique_profile_source UNIQUE (scan_profile_id, source_id);

CREATE INDEX idx_agent_audit_logs_agent ON deprecated.agent_audit_logs USING btree (agent_id, created_at DESC);

CREATE INDEX idx_agent_audit_logs_tenant ON deprecated.agent_audit_logs USING btree (tenant_id, created_at DESC);

CREATE INDEX idx_agent_audit_logs_type ON deprecated.agent_audit_logs USING btree (event_type, created_at DESC);

CREATE INDEX idx_agent_metrics_agent_id ON deprecated.agent_metrics USING btree (agent_id);

CREATE INDEX idx_agent_metrics_agent_type_time ON deprecated.agent_metrics USING btree (agent_id, metric_type, recorded_at DESC);

CREATE INDEX idx_agent_metrics_recorded_at ON deprecated.agent_metrics USING btree (recorded_at DESC);

CREATE INDEX idx_agent_metrics_type ON deprecated.agent_metrics USING btree (metric_type);

CREATE INDEX idx_email_logs_created_at ON deprecated.email_logs USING btree (created_at DESC);

CREATE INDEX idx_email_logs_email_type ON deprecated.email_logs USING btree (email_type);

CREATE INDEX idx_email_logs_recipient ON deprecated.email_logs USING btree (recipient_email);

CREATE INDEX idx_email_logs_status ON deprecated.email_logs USING btree (status);

CREATE INDEX idx_email_logs_tenant_id ON deprecated.email_logs USING btree (tenant_id);

CREATE INDEX idx_registration_tokens_expires ON deprecated.registration_tokens USING btree (expires_at) WHERE (expires_at IS NOT NULL);

CREATE UNIQUE INDEX idx_registration_tokens_hash ON deprecated.registration_tokens USING btree (token_hash) WHERE (is_active = true);

CREATE INDEX idx_registration_tokens_prefix ON deprecated.registration_tokens USING btree (token_prefix);

CREATE INDEX idx_registration_tokens_tenant ON deprecated.registration_tokens USING btree (tenant_id);

CREATE INDEX idx_regression_events_finding ON deprecated.finding_regression_events USING btree (finding_id);

CREATE INDEX idx_regression_events_tenant ON deprecated.finding_regression_events USING btree (tenant_id, detected_at DESC);

CREATE INDEX idx_spts_profile ON deprecated.scan_profile_template_sources USING btree (scan_profile_id);

CREATE INDEX idx_spts_source ON deprecated.scan_profile_template_sources USING btree (source_id);

CREATE INDEX idx_threat_actor_cves_actor ON deprecated.threat_actor_cves USING btree (threat_actor_id);

CREATE INDEX idx_threat_actor_cves_cve ON deprecated.threat_actor_cves USING btree (cve_id);

CREATE INDEX idx_threat_actor_cves_tenant ON deprecated.threat_actor_cves USING btree (tenant_id);

ALTER TABLE ONLY deprecated.agent_audit_logs
    ADD CONSTRAINT agent_audit_logs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.sensors(id) ON DELETE SET NULL;

ALTER TABLE ONLY deprecated.agent_audit_logs
    ADD CONSTRAINT agent_audit_logs_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.sensor_api_keys(id) ON DELETE SET NULL;

ALTER TABLE ONLY deprecated.agent_metrics
    ADD CONSTRAINT agent_metrics_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.sensors(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.email_logs
    ADD CONSTRAINT email_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;

ALTER TABLE ONLY deprecated.email_logs
    ADD CONSTRAINT email_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY deprecated.finding_regression_events
    ADD CONSTRAINT finding_regression_events_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.registration_tokens
    ADD CONSTRAINT registration_tokens_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY deprecated.registration_tokens
    ADD CONSTRAINT registration_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.scan_profile_template_sources
    ADD CONSTRAINT scan_profile_template_sources_scan_profile_id_fkey FOREIGN KEY (scan_profile_id) REFERENCES public.scan_profiles(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.scan_profile_template_sources
    ADD CONSTRAINT scan_profile_template_sources_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.template_sources(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.threat_actor_cves
    ADD CONSTRAINT threat_actor_cves_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY deprecated.threat_actor_cves
    ADD CONSTRAINT threat_actor_cves_threat_actor_id_fkey FOREIGN KEY (threat_actor_id) REFERENCES public.threat_actors(id) ON DELETE CASCADE;

CREATE POLICY agent_audit_logs_tenant_isolation ON deprecated.agent_audit_logs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY email_logs_tenant_isolation ON deprecated.email_logs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY finding_regression_events_tenant_isolation ON deprecated.finding_regression_events USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY registration_tokens_tenant_isolation ON deprecated.registration_tokens USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE POLICY threat_actor_cves_tenant_isolation ON deprecated.threat_actor_cves USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


-- webhook_deliveries and the asset summary views

CREATE VIEW public.v_assets_domain_summary AS
 SELECT id,
    tenant_id,
    name,
    criticality,
    status,
    discovery_tool,
    discovered_at,
    first_seen,
    last_seen,
    jsonb_array_length(COALESCE(((properties -> 'domain'::text) -> 'dns_records'::text), '[]'::jsonb)) AS dns_record_count,
    jsonb_array_length(COALESCE(((properties -> 'domain'::text) -> 'nameservers'::text), '[]'::jsonb)) AS nameserver_count,
    ((properties -> 'domain'::text) ->> 'registrar'::text) AS registrar,
    ((properties -> 'domain'::text) ->> 'expires_at'::text) AS expires_at
   FROM public.assets a
  WHERE ((asset_type)::text = ANY (ARRAY[('domain'::character varying)::text, ('subdomain'::character varying)::text]));

COMMENT ON VIEW public.v_assets_domain_summary IS 'Summary view of domain/subdomain assets with DNS metadata from properties';

CREATE VIEW public.v_assets_http_services AS
 SELECT id,
    tenant_id,
    name,
    criticality,
    status,
    discovery_tool,
    discovered_at,
    first_seen,
    last_seen,
    ((properties -> 'service'::text) ->> 'name'::text) AS service_name,
    ((properties -> 'service'::text) ->> 'version'::text) AS service_version,
    (((properties -> 'service'::text) ->> 'port'::text))::integer AS port,
    ((properties -> 'service'::text) ->> 'protocol'::text) AS protocol,
    (((properties -> 'service'::text) ->> 'tls'::text))::boolean AS tls_enabled,
    (properties ->> 'status_code'::text) AS status_code,
    (properties ->> 'title'::text) AS title,
    (properties -> 'technologies'::text) AS technologies
   FROM public.assets a
  WHERE ((asset_type)::text = ANY (ARRAY[('service'::character varying)::text, ('http_service'::character varying)::text, ('web_application'::character varying)::text]));

COMMENT ON VIEW public.v_assets_http_services IS 'Summary view of HTTP services with technology detection from properties';

CREATE VIEW public.v_assets_ip_summary AS
 SELECT id,
    tenant_id,
    name,
    criticality,
    status,
    discovery_tool,
    discovered_at,
    first_seen,
    last_seen,
    jsonb_array_length(COALESCE(((properties -> 'ip_address'::text) -> 'ports'::text), '[]'::jsonb)) AS open_port_count,
    ((properties -> 'ip_address'::text) ->> 'version'::text) AS ip_version,
    ((properties -> 'ip_address'::text) ->> 'hostname'::text) AS hostname,
    ((properties -> 'ip_address'::text) ->> 'asn'::text) AS asn,
    ((properties -> 'ip_address'::text) ->> 'asn_org'::text) AS asn_org,
    ((properties -> 'ip_address'::text) ->> 'country'::text) AS country
   FROM public.assets a
  WHERE ((asset_type)::text = ANY (ARRAY[('ip_address'::character varying)::text, ('host'::character varying)::text, ('server'::character varying)::text]));

COMMENT ON VIEW public.v_assets_ip_summary IS 'Summary view of IP/host/server assets with port counts and ASN info from properties';

CREATE TABLE public.webhook_deliveries (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL,
    webhook_id uuid NOT NULL,
    event_id uuid,
    event_type character varying(100) NOT NULL,
    payload jsonb NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    response_code integer,
    response_body text,
    response_headers jsonb,
    attempt integer DEFAULT 1 NOT NULL,
    next_retry_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    duration_ms integer,
    CONSTRAINT chk_delivery_status CHECK (((status)::text = ANY (ARRAY[('pending'::character varying)::text, ('success'::character varying)::text, ('failed'::character varying)::text, ('retrying'::character varying)::text])))
);

COMMENT ON TABLE public.webhook_deliveries IS 'Webhook delivery log and retry tracking';

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);

CREATE INDEX idx_webhook_deliveries_created ON public.webhook_deliveries USING btree (created_at DESC);

CREATE INDEX idx_webhook_deliveries_pending ON public.webhook_deliveries USING btree (next_retry_at) WHERE ((status)::text = ANY (ARRAY[('pending'::character varying)::text, ('retrying'::character varying)::text]));

CREATE INDEX idx_webhook_deliveries_status ON public.webhook_deliveries USING btree (status);

CREATE INDEX idx_webhook_deliveries_webhook ON public.webhook_deliveries USING btree (webhook_id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_webhook_id_fkey FOREIGN KEY (webhook_id) REFERENCES public.webhooks(id) ON DELETE CASCADE;

