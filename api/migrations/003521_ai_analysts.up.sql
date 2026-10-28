-- AI analysts (docs/architecture/ai-analysis.md, RFC-132).
--
-- An AI analyst is a service account (users.kind = 'service', migration
-- 001586) plus one profile row. It takes part in triage like a person: it
-- calls the same commands with its own role and data scope, its changes go
-- through the same approvals, and it can never approve (service accounts are
-- not in the approver directory). Every analyst has accountable owners
-- (people or teams); without an active owner or a fresh attestation it pauses.
--
--   ai_analysts        the AI profile of a service account: status, preset,
--                      attestation, budgets, data class ceiling, executor.
--   ai_analyst_owners  the people and teams accountable for an analyst.
--   ai_runs            one row per execution with its provenance (model,
--                      prompt template id and digest, bundle digest, fields
--                      sent and withheld, usage), the analyst that acted and
--                      the accountable owners at that moment. Its status is the
--                      run's logical state; liveness belongs to the job that
--                      executes it (the command lease), and a live run past
--                      its deadline no longer holds the subject's slot.
--
-- finding_activities rows written by an analyst are labeled actor_type 'ai'
-- by a trigger, whatever code path wrote them.
--
-- An analyst has no API key, MCP grant or database role of its own (triggers
-- on api_keys, mcp_oauth_grants and user_roles): it acts only through the
-- platform, which checks its owners, attestation, preset and deny list at
-- every run.
--
-- Live impact: three new tables; triggers on finding_activities, api_keys,
-- mcp_oauth_grants and user_roles (one indexed EXISTS per insert). The seat
-- count stops counting analysts (code). No backfill, no lock on an existing
-- table. The index on finding_activities is built concurrently by the next
-- migration.

CREATE TABLE ai_analysts (
    user_id            uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id          uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    preset             varchar(16)  NOT NULL DEFAULT 'suggest',
    status             varchar(16)  NOT NULL DEFAULT 'active',
    pause_reason       varchar(48),
    data_class_ceiling varchar(16)  NOT NULL DEFAULT 'internal',
    executor           varchar(16)  NOT NULL DEFAULT 'builtin',
    runs_per_hour      integer      NOT NULL DEFAULT 60,
    actions_per_hour   integer      NOT NULL DEFAULT 200,
    tokens_month       integer      NOT NULL DEFAULT 0,
    attested_at        timestamptz  NOT NULL DEFAULT now(),
    attested_by        uuid         REFERENCES users(id) ON DELETE SET NULL,
    attest_due_at      timestamptz  NOT NULL,
    created_by         uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_analysts PRIMARY KEY (user_id),
    CONSTRAINT uq_ai_analysts_user_tenant UNIQUE (user_id, tenant_id),
    CONSTRAINT chk_ai_analysts_preset CHECK (preset IN ('suggest', 'triage')),
    CONSTRAINT chk_ai_analysts_status CHECK (status IN ('active', 'paused', 'disabled')),
    CONSTRAINT chk_ai_analysts_pause CHECK ((status = 'active') = (pause_reason IS NULL)
        AND (pause_reason IS NULL OR pause_reason ~ '^[a-z_]{1,48}$')),
    CONSTRAINT chk_ai_analysts_class CHECK (data_class_ceiling IN ('public', 'internal', 'restricted', 'tenant_only')),
    CONSTRAINT chk_ai_analysts_executor CHECK (executor IN ('builtin', 'platform_worker', 'tenant_worker', 'external')),
    CONSTRAINT chk_ai_analysts_budgets CHECK (runs_per_hour BETWEEN 1 AND 10000
        AND actions_per_hour BETWEEN 1 AND 100000 AND tokens_month >= 0),
    CONSTRAINT chk_ai_analysts_attest CHECK (attest_due_at > attested_at)
);
CREATE INDEX idx_ai_analysts_tenant ON ai_analysts (tenant_id);
CREATE INDEX idx_ai_analysts_attest_due ON ai_analysts (attest_due_at) WHERE status = 'active';
CREATE INDEX idx_ai_analysts_attested_by ON ai_analysts (attested_by) WHERE attested_by IS NOT NULL;
CREATE INDEX idx_ai_analysts_created_by ON ai_analysts (created_by) WHERE created_by IS NOT NULL;
COMMENT ON TABLE ai_analysts IS
    'The AI profile of a service account: it acts like a person through the same commands, with its own role and data scope, never approves, and pauses without an active accountable owner or a fresh attestation.';
COMMENT ON COLUMN ai_analysts.pause_reason IS
    'Why a paused or disabled analyst does not run: no_active_owner, attestation_expired, admin, ...';

CREATE FUNCTION refuse_ai_analyst_non_service() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users u
                   WHERE u.id = NEW.user_id AND u.kind = 'service' AND u.service_tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'an AI analyst must be a service account of the same organization'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_ai_analyst_non_service
    BEFORE INSERT OR UPDATE OF user_id, tenant_id ON ai_analysts
    FOR EACH ROW EXECUTE FUNCTION refuse_ai_analyst_non_service();

CREATE POLICY ai_analysts_tenant_isolation ON ai_analysts
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_analyst_owners (
    id         uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    analyst_id uuid        NOT NULL,
    user_id    uuid        REFERENCES users(id) ON DELETE CASCADE,
    group_id   uuid        REFERENCES groups(id) ON DELETE CASCADE,
    added_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_analyst_owners PRIMARY KEY (id),
    CONSTRAINT fk_ai_analyst_owners_analyst FOREIGN KEY (analyst_id, tenant_id)
        REFERENCES ai_analysts (user_id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_ai_analyst_owners_one CHECK ((user_id IS NULL) <> (group_id IS NULL))
);
CREATE UNIQUE INDEX uq_ai_analyst_owners_user ON ai_analyst_owners (analyst_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX uq_ai_analyst_owners_group ON ai_analyst_owners (analyst_id, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_ai_analyst_owners_tenant ON ai_analyst_owners (tenant_id, analyst_id);
CREATE INDEX idx_ai_analyst_owners_user ON ai_analyst_owners (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_ai_analyst_owners_group ON ai_analyst_owners (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_ai_analyst_owners_added_by ON ai_analyst_owners (added_by) WHERE added_by IS NOT NULL;
COMMENT ON TABLE ai_analyst_owners IS
    'People and teams accountable for an AI analyst. A person owner is a person (never a service account) and a member of the organization; a team owner is a team of the organization.';

CREATE FUNCTION refuse_foreign_ai_analyst_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM users u JOIN tenant_members m ON m.user_id = u.id AND m.tenant_id = NEW.tenant_id
        WHERE u.id = NEW.user_id AND u.kind = 'person') THEN
        RAISE EXCEPTION 'an AI analyst owner must be a person in the same organization'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.group_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM groups g WHERE g.id = NEW.group_id AND g.tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'an AI analyst owner team must belong to the same organization'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_foreign_ai_analyst_owner
    BEFORE INSERT OR UPDATE ON ai_analyst_owners
    FOR EACH ROW EXECUTE FUNCTION refuse_foreign_ai_analyst_owner();

CREATE POLICY ai_analyst_owners_tenant_isolation ON ai_analyst_owners
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE TABLE ai_runs (
    id                     uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id              uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    analyst_id             uuid,
    use_case               varchar(32) NOT NULL,
    kind                   varchar(48) NOT NULL,
    subject_type           varchar(16) NOT NULL,
    subject_id             uuid        NOT NULL,
    executor               varchar(16) NOT NULL DEFAULT 'builtin',
    sensor_id              uuid,
    command_id             uuid,
    status                 varchar(20) NOT NULL DEFAULT 'queued',
    data_class             varchar(16) NOT NULL DEFAULT 'internal',
    fields_sent            text[]      NOT NULL DEFAULT '{}',
    fields_withheld        text[]      NOT NULL DEFAULT '{}',
    bundle_digest          varchar(71),
    grant_digest           varchar(71),
    prompt_template_id     varchar(64),
    prompt_template_digest varchar(71),
    output_schema          varchar(64),
    provider               varchar(50),
    model                  varchar(128),
    model_params           jsonb       NOT NULL DEFAULT '{}',
    steps                  integer     NOT NULL DEFAULT 0,
    tool_calls             integer     NOT NULL DEFAULT 0,
    actions                integer     NOT NULL DEFAULT 0,
    tokens_in              integer     NOT NULL DEFAULT 0,
    tokens_out             integer     NOT NULL DEFAULT 0,
    cost_micro_usd         bigint      NOT NULL DEFAULT 0,
    duration_ms            integer,
    run_record_ref         text,
    run_record_digest      varchar(71),
    error_code             varchar(64),
    shadow                 boolean     NOT NULL DEFAULT false,
    triggered_by           uuid        REFERENCES users(id) ON DELETE SET NULL,
    trigger                varchar(16) NOT NULL DEFAULT 'on_demand',
    accountable            jsonb       NOT NULL DEFAULT '[]',
    legacy_output          jsonb,
    deadline_at            timestamptz,
    started_at             timestamptz,
    completed_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ai_runs PRIMARY KEY (id),
    CONSTRAINT uq_ai_runs_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT fk_ai_runs_analyst FOREIGN KEY (analyst_id, tenant_id)
        REFERENCES ai_analysts (user_id, tenant_id) ON DELETE SET NULL (analyst_id),
    CONSTRAINT chk_ai_runs_analyst CHECK (analyst_id IS NOT NULL OR kind ~ '\.legacy$' OR status IN ('completed', 'failed', 'canceled', 'refused')),
    CONSTRAINT chk_ai_runs_use_case CHECK (use_case IN ('triage', 'remediation', 'summary')),
    CONSTRAINT chk_ai_runs_kind CHECK (kind ~ '^[a-z_]{1,32}\.(v[0-9]{1,3}|legacy)$'),
    CONSTRAINT chk_ai_runs_subject_type CHECK (subject_type IN ('finding', 'asset', 'cve', 'attack_path', 'bounty_report')),
    CONSTRAINT chk_ai_runs_executor CHECK (executor IN ('builtin', 'platform_worker', 'tenant_worker', 'external')),
    CONSTRAINT chk_ai_runs_worker CHECK ((executor IN ('platform_worker', 'tenant_worker')) = (sensor_id IS NOT NULL)),
    CONSTRAINT chk_ai_runs_status CHECK (status IN ('queued', 'running', 'waiting_tool', 'waiting_approval',
        'completed', 'failed', 'canceled', 'refused')),
    CONSTRAINT chk_ai_runs_data_class CHECK (data_class IN ('public', 'internal', 'restricted', 'tenant_only')),
    CONSTRAINT chk_ai_runs_fields CHECK (cardinality(fields_sent) <= 128 AND cardinality(fields_withheld) <= 128),
    CONSTRAINT chk_ai_runs_digests CHECK (
        (bundle_digest IS NULL OR bundle_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (grant_digest IS NULL OR grant_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (prompt_template_digest IS NULL OR prompt_template_digest ~ '^sha256:[0-9a-f]{64}$')
        AND (run_record_digest IS NULL OR run_record_digest ~ '^sha256:[0-9a-f]{64}$')),
    CONSTRAINT chk_ai_runs_model_params CHECK (octet_length(model_params::text) <= 2048),
    CONSTRAINT chk_ai_runs_usage CHECK (steps >= 0 AND tool_calls >= 0 AND actions >= 0 AND tokens_in >= 0
        AND tokens_out >= 0 AND cost_micro_usd >= 0 AND (duration_ms IS NULL OR duration_ms >= 0)),
    CONSTRAINT chk_ai_runs_error_code CHECK (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,64}$'),
    CONSTRAINT chk_ai_runs_trigger CHECK (trigger IN ('on_demand', 'on_ingest', 'workflow', 'schedule', 'mention')),
    CONSTRAINT chk_ai_runs_accountable CHECK (jsonb_typeof(accountable) = 'array' AND octet_length(accountable::text) <= 4096),
    CONSTRAINT chk_ai_runs_legacy CHECK (legacy_output IS NULL OR (jsonb_typeof(legacy_output) = 'object'
        AND octet_length(legacy_output::text) <= 65536))
);
CREATE INDEX idx_ai_runs_subject ON ai_runs (tenant_id, subject_type, subject_id, created_at DESC);
CREATE INDEX idx_ai_runs_tenant_created ON ai_runs (tenant_id, created_at DESC);
CREATE INDEX idx_ai_runs_analyst_created ON ai_runs (analyst_id, created_at DESC) WHERE analyst_id IS NOT NULL;
CREATE INDEX idx_ai_runs_triggered_by ON ai_runs (triggered_by) WHERE triggered_by IS NOT NULL;
CREATE UNIQUE INDEX uq_ai_runs_in_flight ON ai_runs (tenant_id, use_case, subject_id)
    WHERE status IN ('queued', 'running', 'waiting_tool', 'waiting_approval') AND NOT shadow;
COMMENT ON TABLE ai_runs IS
    'One execution of an AI use case with its provenance, the analyst that acted and the accountable owners at that moment. Tenant-scoped; deleted with the organization.';
COMMENT ON COLUMN ai_runs.error_code IS 'Fixed failure code only; never provider or model text.';
COMMENT ON COLUMN ai_runs.accountable IS 'The analyst''s accountable owners when the run started: [{kind, id, name}].';

CREATE POLICY ai_runs_tenant_isolation ON ai_runs
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

CREATE FUNCTION label_ai_analyst_activity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.actor_id IS NOT NULL AND NEW.actor_type <> 'ai'
       AND EXISTS (SELECT 1 FROM ai_analysts a WHERE a.user_id = NEW.actor_id AND a.tenant_id = NEW.tenant_id) THEN
        NEW.actor_type := 'ai';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_label_ai_analyst_activity
    BEFORE INSERT ON finding_activities
    FOR EACH ROW EXECUTE FUNCTION label_ai_analyst_activity();

-- An analyst acts only through the platform's executor, as a principal the
-- platform resolves at every run (owners, attestation, preset, deny list).
-- It has no credential of its own and no database role: an API key, an MCP
-- grant or a role row for it would bypass those checks, so the schema
-- refuses them whatever code path writes them.
CREATE FUNCTION refuse_ai_analyst_credential() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM ai_analysts a WHERE a.user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'an AI analyst has no API key, MCP grant or role of its own'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_ai_analyst_api_key
    BEFORE INSERT OR UPDATE OF user_id ON api_keys
    FOR EACH ROW EXECUTE FUNCTION refuse_ai_analyst_credential();
CREATE TRIGGER trigger_refuse_ai_analyst_mcp_grant
    BEFORE INSERT OR UPDATE OF user_id ON mcp_oauth_grants
    FOR EACH ROW EXECUTE FUNCTION refuse_ai_analyst_credential();
CREATE TRIGGER trigger_refuse_ai_analyst_role
    BEFORE INSERT OR UPDATE OF user_id ON user_roles
    FOR EACH ROW EXECUTE FUNCTION refuse_ai_analyst_credential();

-- A service account becomes an analyst only while it holds none of those.
CREATE FUNCTION refuse_ai_analyst_with_credentials() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM api_keys k WHERE k.user_id = NEW.user_id AND k.status = 'active')
       OR EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.user_id = NEW.user_id AND g.revoked_at IS NULL)
       OR EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'an AI analyst cannot be made from a service account that has keys, grants or roles'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_ai_analyst_with_credentials
    BEFORE INSERT ON ai_analysts
    FOR EACH ROW EXECUTE FUNCTION refuse_ai_analyst_with_credentials();
