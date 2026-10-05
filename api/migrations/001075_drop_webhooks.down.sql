-- Recreate the retired outbound webhooks table, empty (the configuration rows
-- dropped by the up migration are not restored).

CREATE TABLE IF NOT EXISTS webhooks (
    id uuid DEFAULT uuid_generate_v7() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    url character varying(1000) NOT NULL,
    secret_encrypted bytea,
    event_types text[] DEFAULT '{}'::text[] NOT NULL,
    severity_threshold character varying(20) DEFAULT 'medium'::character varying,
    asset_group_ids uuid[] DEFAULT '{}'::uuid[],
    tags text[] DEFAULT '{}'::text[],
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    max_retries integer DEFAULT 3 NOT NULL,
    retry_interval_seconds integer DEFAULT 60 NOT NULL,
    total_sent integer DEFAULT 0 NOT NULL,
    total_failed integer DEFAULT 0 NOT NULL,
    last_sent_at timestamp with time zone,
    last_error text,
    last_error_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_webhook_severity CHECK (((severity_threshold)::text = ANY (ARRAY[('critical'::character varying)::text, ('high'::character varying)::text, ('medium'::character varying)::text, ('low'::character varying)::text, ('info'::character varying)::text]))),
    CONSTRAINT chk_webhook_status CHECK (((status)::text = ANY (ARRAY[('active'::character varying)::text, ('disabled'::character varying)::text, ('error'::character varying)::text]))),
    CONSTRAINT webhooks_pkey PRIMARY KEY (id),
    CONSTRAINT unique_webhook_name UNIQUE (tenant_id, name),
    CONSTRAINT webhooks_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT webhooks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

COMMENT ON TABLE webhooks IS 'Retired (owner decision B9): outbound webhooks never had a delivery worker; no code reads or writes this table.';
COMMENT ON COLUMN webhooks.secret_encrypted IS 'HMAC signing secret for payload verification';
COMMENT ON COLUMN webhooks.event_types IS 'Events to send: finding.created, scan.completed, etc.';

CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks USING btree (tenant_id) WHERE ((status)::text = 'active'::text);
CREATE INDEX IF NOT EXISTS idx_webhooks_events ON webhooks USING gin (event_types);
CREATE INDEX IF NOT EXISTS idx_webhooks_status ON webhooks USING btree (status);

DROP TRIGGER IF EXISTS update_webhooks_updated_at ON webhooks;
CREATE TRIGGER update_webhooks_updated_at BEFORE UPDATE ON webhooks FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP POLICY IF EXISTS webhooks_tenant_isolation ON webhooks;
CREATE POLICY webhooks_tenant_isolation ON webhooks USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
