-- Per-item dispositions on ingest receipts, the policy that decided each
-- item, versioned policy snapshots, and the ingest side-effect outbox
-- (docs/rfcs/RFC-122-ingest-receipts.md, "Dispositions").
--
--   finding_ingest_actions  gains the dispositions that keep a finding
--                           (suppressed, held) and the policy that decided
--                           the item (policy kind, rule id, policy version).
--   ingest_receipt_items    the items a receipt did NOT turn into a finding:
--                           filtered, out_of_scope, rejected, quarantined;
--                           an identity key, the asset, tool, title (cut to
--                           200 characters) and severity, a fixed reason
--                           code and the deciding policy; never evidence.
--   ingest_policy_versions  a per-tenant counter every write to a policy
--                           table bumps (suppression rules, scope
--                           exclusions), so the ingest worker reuses its
--                           in-memory policy snapshot until it changes.
--   ingest_jobs.kind        gains 'side_effects': the after-commit work of
--                           an ingest batch (automations on new findings),
--                           durable and batched instead of a goroutine.
--
-- Live impact: a check constraint swap on finding_ingest_actions validated
-- against its rows (all are in the old set), three nullable columns, one
-- new empty table, one small table filled per tenant on first policy write,
-- two row triggers on two small configuration tables. No backfill.

ALTER TABLE finding_ingest_actions DROP CONSTRAINT IF EXISTS chk_finding_ingest_actions_action;
ALTER TABLE finding_ingest_actions
    ADD CONSTRAINT chk_finding_ingest_actions_action
        CHECK (action IN ('created', 'still_detected', 'reopened', 'closed', 'suppressed', 'held'));
ALTER TABLE finding_ingest_actions
    ADD COLUMN IF NOT EXISTS policy         varchar(32),
    ADD COLUMN IF NOT EXISTS policy_id      uuid,
    ADD COLUMN IF NOT EXISTS policy_version bigint;
COMMENT ON COLUMN finding_ingest_actions.policy IS
    'The policy kind that decided the item (suppression_rule, ...); NULL when no policy did (created, still_detected, reopened, closed).';

CREATE TABLE IF NOT EXISTS ingest_receipt_items (
    tenant_id      uuid         NOT NULL,
    receipt_id     uuid         NOT NULL,
    item_key       varchar(64)  NOT NULL,
    disposition    varchar(16)  NOT NULL,
    reason_code    varchar(32)  NOT NULL,
    asset_id       uuid,
    tool_name      varchar(100),
    title          varchar(200),
    severity       varchar(16),
    policy         varchar(32),
    policy_id      uuid,
    policy_version bigint,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ingest_receipt_items PRIMARY KEY (receipt_id, item_key),
    CONSTRAINT fk_ingest_receipt_items_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_ingest_receipt_items_receipt FOREIGN KEY (receipt_id) REFERENCES ingest_receipts (id) ON DELETE CASCADE,
    CONSTRAINT chk_ingest_receipt_items_disposition
        CHECK (disposition IN ('filtered', 'out_of_scope', 'rejected', 'quarantined'))
);
CREATE INDEX IF NOT EXISTS idx_ingest_receipt_items_tenant ON ingest_receipt_items (tenant_id, created_at);
COMMENT ON TABLE ingest_receipt_items IS
    'Items a receipt did not turn into a finding (filtered, out_of_scope, rejected, quarantined), with a fixed reason code and the deciding policy and version. At most 50,000 per receipt with the action rows; kept 90 days. No evidence, no secrets.';

CREATE TABLE IF NOT EXISTS ingest_policy_versions (
    tenant_id  uuid        NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    version    bigint      NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE ingest_policy_versions IS
    'Per-tenant version of the policies ingest applies (suppression rules, scope exclusions); bumped by trigger on every write to them. The ingest worker reloads its policy snapshot when it changes.';

CREATE OR REPLACE FUNCTION bump_ingest_policy_version() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    t uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- A delete only bumps an existing row: when the tenant itself is
        -- being deleted (its rules cascade), nothing is inserted for it.
        UPDATE ingest_policy_versions SET version = version + 1, updated_at = now()
        WHERE tenant_id = OLD.tenant_id;
        RETURN NULL;
    END IF;
    t := NEW.tenant_id;
    INSERT INTO ingest_policy_versions (tenant_id, version, updated_at)
    VALUES (t, 2, now())
    ON CONFLICT (tenant_id) DO UPDATE
        SET version = ingest_policy_versions.version + 1, updated_at = now();
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_suppression_rules_policy_version ON suppression_rules;
CREATE TRIGGER trg_suppression_rules_policy_version
    AFTER INSERT OR UPDATE OR DELETE ON suppression_rules
    FOR EACH ROW EXECUTE FUNCTION bump_ingest_policy_version();
DROP TRIGGER IF EXISTS trg_scope_exclusions_policy_version ON scope_exclusions;
CREATE TRIGGER trg_scope_exclusions_policy_version
    AFTER INSERT OR UPDATE OR DELETE ON scope_exclusions
    FOR EACH ROW EXECUTE FUNCTION bump_ingest_policy_version();

ALTER TABLE ingest_jobs DROP CONSTRAINT IF EXISTS chk_ingest_jobs_kind;
ALTER TABLE ingest_jobs
    ADD CONSTRAINT chk_ingest_jobs_kind CHECK (kind IN ('sensor', 'ci_results', 'finding_import', 'side_effects'));

-- Row-level security policies in shadow mode, like the other tenant tables.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ingest_receipt_items', 'ingest_policy_versions'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
