-- Exploration layer (docs/rfcs/RFC-153-exploration.md): leads, typed links and
-- append-only verdicts. The layer references existing records (assets,
-- findings, scan runs) and never copies them. New tables only; no existing
-- table or column changes.
--
-- Tenant isolation is enforced by the database on every reference: each end
-- of a link is a typed column with a composite foreign key on (tenant_id, id),
-- never a polymorphic id, so a row can only point at rows of its own tenant.

-- One exploration is one objective with its own budget. Every tenant has at
-- most one continuous exploration (the rules' home); campaigns and ad hoc
-- investigations come later.
CREATE TABLE IF NOT EXISTS explorations (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    kind        text        NOT NULL,
    title       text        NOT NULL,
    status      text        NOT NULL DEFAULT 'open',
    budget      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    row_version integer     NOT NULL DEFAULT 1,
    CONSTRAINT explorations_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_explorations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_explorations_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_explorations_kind CHECK (kind IN ('continuous', 'campaign', 'investigation')),
    CONSTRAINT chk_explorations_status CHECK (status IN ('open', 'paused', 'settled', 'archived')),
    CONSTRAINT chk_explorations_title CHECK (char_length(title) BETWEEN 1 AND 200),
    CONSTRAINT chk_explorations_budget CHECK (jsonb_typeof(budget) = 'object' AND octet_length(budget::text) <= 4096)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_explorations_continuous ON explorations (tenant_id) WHERE kind = 'continuous';

COMMENT ON TABLE explorations IS
    'One objective of the exploration layer with its own budget; at most one continuous exploration per tenant.';

-- A lead is an open question with a typed next action, justified by existing
-- records (exploration_links rel derived_from). The action is a capability of
-- the stage catalog plus params; free text is only the rationale and is
-- never executed. Scores, tiers and states are written by code only.
CREATE TABLE IF NOT EXISTS exploration_leads (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    exploration_id     uuid        NOT NULL,
    lead_type          text        NOT NULL,
    state              text        NOT NULL,
    capability         text,
    params             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    action_hash        text,
    tier               smallint,
    subject_asset_id   uuid,
    subject_finding_id uuid,
    reason_code        text        NOT NULL,
    rationale          text        NOT NULL DEFAULT '',
    origin             text        NOT NULL,
    origin_ref         text        NOT NULL,
    likelihood         text        NOT NULL DEFAULT 'medium',
    score              real        NOT NULL DEFAULT 0,
    score_inputs       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    dedup_key          text        NOT NULL,
    blocked_reason     text        NOT NULL DEFAULT '',
    attempts           smallint    NOT NULL DEFAULT 0,
    next_attempt_at    timestamptz,
    approved_by        uuid,
    approved_at        timestamptz,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    closed_at          timestamptz,
    row_version        integer     NOT NULL DEFAULT 1,
    CONSTRAINT exploration_leads_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_exploration_leads_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_leads_exploration FOREIGN KEY (tenant_id, exploration_id)
        REFERENCES explorations (tenant_id, id) ON DELETE CASCADE,
    -- A removed subject keeps the lead (never lose information); only the
    -- subject column is cleared, never the tenant.
    CONSTRAINT fk_exploration_leads_subject_asset FOREIGN KEY (tenant_id, subject_asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE SET NULL (subject_asset_id),
    CONSTRAINT fk_exploration_leads_subject_finding FOREIGN KEY (tenant_id, subject_finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE SET NULL (subject_finding_id),
    CONSTRAINT fk_exploration_leads_approved_by FOREIGN KEY (approved_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_exploration_leads_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_exploration_leads_type CHECK (lead_type ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(lead_type) <= 64),
    CONSTRAINT chk_exploration_leads_state CHECK (state IN (
        'proposed', 'awaiting_approval', 'open', 'running', 'blocked',
        'done', 'refuted', 'exhausted', 'dismissed', 'superseded')),
    CONSTRAINT chk_exploration_leads_capability CHECK (
        capability IS NULL OR (capability ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(capability) <= 64)),
    CONSTRAINT chk_exploration_leads_action CHECK ((capability IS NULL) = (tier IS NULL) AND (capability IS NULL) = (action_hash IS NULL)),
    CONSTRAINT chk_exploration_leads_tier CHECK (tier IS NULL OR tier BETWEEN 0 AND 2),
    CONSTRAINT chk_exploration_leads_subject CHECK (num_nonnulls(subject_asset_id, subject_finding_id) <= 1),
    CONSTRAINT chk_exploration_leads_origin CHECK (origin IN ('rule', 'user', 'ai_agent', 'system')),
    CONSTRAINT chk_exploration_leads_likelihood CHECK (likelihood IN ('low', 'medium', 'high')),
    CONSTRAINT chk_exploration_leads_text CHECK (
        char_length(reason_code) <= 128 AND char_length(rationale) <= 2000 AND char_length(origin_ref) <= 200
        AND char_length(dedup_key) <= 512 AND char_length(blocked_reason) <= 128
        AND (action_hash IS NULL OR char_length(action_hash) = 64)),
    CONSTRAINT chk_exploration_leads_json CHECK (
        jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 8192
        AND jsonb_typeof(score_inputs) = 'object' AND octet_length(score_inputs::text) <= 4096),
    CONSTRAINT chk_exploration_leads_attempts CHECK (attempts >= 0),
    CONSTRAINT chk_exploration_leads_closed CHECK (
        (state IN ('done', 'refuted', 'exhausted', 'dismissed', 'superseded')) = (closed_at IS NOT NULL))
);

-- One live lead per question.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploration_leads_live_dedup ON exploration_leads (tenant_id, exploration_id, dedup_key)
    WHERE state IN ('proposed', 'awaiting_approval', 'open', 'running', 'blocked');
-- The frontier: open leads by score.
CREATE INDEX IF NOT EXISTS ix_exploration_leads_frontier ON exploration_leads (tenant_id, exploration_id, score DESC, created_at)
    WHERE state = 'open';
-- The page's groups and the controller's settlement and recheck passes.
CREATE INDEX IF NOT EXISTS ix_exploration_leads_state ON exploration_leads (tenant_id, state, updated_at DESC);
-- "Next steps" of an asset; a finding's leads.
CREATE INDEX IF NOT EXISTS ix_exploration_leads_subject_asset ON exploration_leads (tenant_id, subject_asset_id, updated_at DESC)
    WHERE subject_asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_exploration_leads_subject_finding ON exploration_leads (tenant_id, subject_finding_id)
    WHERE subject_finding_id IS NOT NULL;

COMMENT ON TABLE exploration_leads IS
    'Open questions with a typed next action (a stage catalog capability), opened by rules or people and justified by derived_from links; scored, capped and dispatched by code through the dispatch gate. Kept forever.';
COMMENT ON COLUMN exploration_leads.rationale IS
    'Free text shown to people; never executed. Untrusted, length-limited, rendered escaped.';
COMMENT ON COLUMN exploration_leads.action_hash IS
    'sha256 (hex) of the canonical action (lead type, capability, params, subject); the same action is never dispatched twice for one lead.';

-- Typed links of a lead: what it was derived from, the run it was dispatched
-- as, and what that step yielded (including "nothing found"). Each link has
-- exactly one typed end; the end's kind is kept when the record it pointed
-- at is removed (the column is cleared, the link stays).
CREATE TABLE IF NOT EXISTS exploration_links (
    tenant_id      uuid        NOT NULL,
    id             bigint      GENERATED ALWAYS AS IDENTITY,
    lead_id        uuid        NOT NULL,
    rel            text        NOT NULL,
    end_kind       text        NOT NULL,
    asset_id       uuid,
    finding_id     uuid,
    scan_run_id    uuid,
    ref_lead_id    uuid,
    effect         text,
    outcome_reason text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT exploration_links_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_exploration_links_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_links_lead FOREIGN KEY (tenant_id, lead_id)
        REFERENCES exploration_leads (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_links_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id),
    CONSTRAINT fk_exploration_links_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE SET NULL (finding_id),
    CONSTRAINT fk_exploration_links_scan_run FOREIGN KEY (tenant_id, scan_run_id)
        REFERENCES scan_runs (tenant_id, id) ON DELETE SET NULL (scan_run_id),
    CONSTRAINT fk_exploration_links_ref_lead FOREIGN KEY (tenant_id, ref_lead_id)
        REFERENCES exploration_leads (tenant_id, id) ON DELETE SET NULL (ref_lead_id),
    CONSTRAINT chk_exploration_links_rel CHECK (rel IN ('derived_from', 'dispatched_as', 'yields')),
    CONSTRAINT chk_exploration_links_end_kind CHECK (end_kind IN ('asset', 'finding', 'scan_run', 'lead')),
    CONSTRAINT chk_exploration_links_one_end CHECK (num_nonnulls(asset_id, finding_id, scan_run_id, ref_lead_id) <= 1),
    CONSTRAINT chk_exploration_links_end_matches CHECK (
        (asset_id IS NULL OR end_kind = 'asset') AND (finding_id IS NULL OR end_kind = 'finding')
        AND (scan_run_id IS NULL OR end_kind = 'scan_run') AND (ref_lead_id IS NULL OR end_kind = 'lead')),
    CONSTRAINT chk_exploration_links_dispatch CHECK (rel <> 'dispatched_as' OR end_kind = 'scan_run'),
    CONSTRAINT chk_exploration_links_effect CHECK (
        effect IS NULL OR effect IN ('created', 'changed', 'confirmed', 'not_found', 'blocked', 'failed')),
    CONSTRAINT chk_exploration_links_reason CHECK (char_length(outcome_reason) <= 128)
);

-- One link per lead, relation and end: a step is recorded once, and the same
-- run is never dispatched twice for one lead.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploration_links_asset ON exploration_links (tenant_id, lead_id, rel, asset_id)
    WHERE asset_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploration_links_finding ON exploration_links (tenant_id, lead_id, rel, finding_id)
    WHERE finding_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploration_links_scan_run ON exploration_links (tenant_id, lead_id, rel, scan_run_id)
    WHERE scan_run_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploration_links_ref_lead ON exploration_links (tenant_id, lead_id, rel, ref_lead_id)
    WHERE ref_lead_id IS NOT NULL;
-- Reverse reads: which leads an asset, a finding or a run is part of.
CREATE INDEX IF NOT EXISTS ix_exploration_links_asset ON exploration_links (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_exploration_links_finding ON exploration_links (tenant_id, finding_id) WHERE finding_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_exploration_links_scan_run ON exploration_links (tenant_id, scan_run_id) WHERE scan_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_exploration_links_ref_lead ON exploration_links (tenant_id, ref_lead_id) WHERE ref_lead_id IS NOT NULL;

COMMENT ON TABLE exploration_links IS
    'Typed links of a lead: derived_from (the evidence that justified it), dispatched_as (the run it started), yields (what that run produced, with not_found as a result). One typed end per row, each with a composite tenant foreign key.';

-- Verdicts on a lead are append-only: a correction is a new row. The only
-- change a row ever takes is clearing decided_by when that account is
-- deleted (the foreign key's SET NULL); it goes only with its lead.
CREATE TABLE IF NOT EXISTS exploration_verdicts (
    tenant_id  uuid        NOT NULL,
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    lead_id    uuid        NOT NULL,
    verdict    text        NOT NULL,
    tier       text        NOT NULL,
    checker    text        NOT NULL,
    evidence   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    reason     text        NOT NULL DEFAULT '',
    decided_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT exploration_verdicts_pkey PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_exploration_verdicts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_verdicts_lead FOREIGN KEY (tenant_id, lead_id)
        REFERENCES exploration_leads (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_verdicts_decided_by FOREIGN KEY (decided_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_exploration_verdicts_verdict CHECK (verdict IN ('proven', 'refuted', 'inconclusive')),
    CONSTRAINT chk_exploration_verdicts_tier CHECK (tier IN ('deterministic', 'human', 'heuristic', 'ai')),
    -- A person's verdict names the person; any other names its checker.
    CONSTRAINT chk_exploration_verdicts_human CHECK (tier <> 'human' OR checker LIKE 'user:%'),
    CONSTRAINT chk_exploration_verdicts_text CHECK (char_length(checker) <= 200 AND char_length(reason) <= 2000),
    CONSTRAINT chk_exploration_verdicts_evidence CHECK (jsonb_typeof(evidence) = 'array' AND octet_length(evidence::text) <= 16384)
);
CREATE INDEX IF NOT EXISTS ix_exploration_verdicts_lead ON exploration_verdicts (tenant_id, lead_id, created_at);

COMMENT ON TABLE exploration_verdicts IS
    'Append-only verdicts on a lead (proven, refuted, inconclusive) with the checker and evidence references (never bodies). Proven only from a deterministic check or a person with evidence.';

CREATE OR REPLACE FUNCTION exploration_verdicts_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- The foreign key clearing a deleted account is the one allowed change.
        IF OLD.decided_by IS NOT NULL AND NEW.decided_by IS NULL
           AND (to_jsonb(NEW) - 'decided_by') = (to_jsonb(OLD) - 'decided_by')
           AND NOT EXISTS (SELECT 1 FROM users WHERE id = OLD.decided_by) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'exploration_verdicts is append-only: add a new verdict instead';
    END IF;
    -- DELETE: only together with its lead (lead, exploration or tenant deleted).
    IF EXISTS (SELECT 1 FROM exploration_leads WHERE tenant_id = OLD.tenant_id AND id = OLD.lead_id) THEN
        RAISE EXCEPTION 'exploration_verdicts is append-only: a verdict goes only with its lead';
    END IF;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_exploration_verdicts_append_only ON exploration_verdicts;
CREATE TRIGGER trg_exploration_verdicts_append_only
    BEFORE UPDATE OR DELETE ON exploration_verdicts
    FOR EACH ROW EXECUTE FUNCTION exploration_verdicts_append_only();

-- Row-level security in shadow mode, like the other tenant tables.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['explorations', 'exploration_leads', 'exploration_links', 'exploration_verdicts'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format('CREATE POLICY %I ON %I USING ((tenant_id = (NULLIF(current_setting(''app.current_tenant_id'', true), ''''))::uuid) OR (current_setting(''app.is_platform_admin'', true) = ''true''))',
                       t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
