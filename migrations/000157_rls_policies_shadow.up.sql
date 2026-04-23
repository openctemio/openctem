-- Row-level-security policies (shadow mode).
--
-- RLSContextMiddleware already sets `app.current_tenant_id` on every
-- authenticated request and `app.is_platform_admin = true` on admin
-- routes. This migration defines the POLICIES those session vars
-- will match against once RLS is turned on.
--
-- SHADOW MODE: policies are CREATEd but RLS is NOT enabled on the
-- tables. Postgres ignores policies on RLS-disabled tables, so this
-- migration has zero runtime effect. A follow-up ops migration flips
-- each table with ALTER TABLE … ENABLE ROW LEVEL SECURITY once the
-- operator has confirmed:
--
--   1. Every read path on that table goes through RLSContextMiddleware
--      (not a direct db.QueryContext from a worker/cron).
--   2. Platform-admin paths use PlatformAdminRLSMiddleware.
--   3. The integration test suite passes with RLS enabled on the
--      target table.
--
-- Policy shape for every tenant-scoped table:
--
--   USING ( tenant_id = current_setting('app.current_tenant_id', true)::uuid
--        OR current_setting('app.is_platform_admin', true) = 'true' )
--
-- The second `true` argument to current_setting makes it return empty
-- instead of erroring when the var is unset, so a background worker
-- that forgets to set the var gets ZERO rows (fail-closed) rather
-- than crashing.

-- Top 20 tenant-scoped tables — ranked by query volume + data
-- sensitivity. The rest of the ~62 tables land in a follow-up
-- migration once this batch is validated in production.
DO $$
DECLARE
    t TEXT;
    tables TEXT[] := ARRAY[
        -- assets / findings / exposures (hot path)
        'assets',
        'findings',
        'exposures',
        'finding_comments',
        'finding_approvals',
        'finding_activity',
        'asset_groups',
        'asset_relationships',
        -- vulnerability / IOC / threat intel
        'components',
        'iocs',
        'ioc_matches',
        'runtime_telemetry_events',
        -- CTEM cycle + scoring
        'ctem_cycles',
        'priority_class_audit_log',
        'compensating_controls',
        -- scanning / ingestion
        'scans',
        'pipelines',
        'tool_executions',
        -- audit + notifications
        'audit_logs',
        'notification_outbox'
    ];
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        -- Skip tables that don't exist in this edition — the same
        -- migration runs across OSS + enterprise schemas.
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = t
        ) THEN
            RAISE NOTICE 'rls shadow: skipping missing table %', t;
            CONTINUE;
        END IF;

        -- Skip tables that don't have tenant_id — not everything in
        -- the list is guaranteed to, schema evolves.
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = t
               AND column_name = 'tenant_id'
        ) THEN
            RAISE NOTICE 'rls shadow: table % has no tenant_id column; skipped', t;
            CONTINUE;
        END IF;

        -- Tenant-isolation policy. Idempotent: drop-if-exists then create.
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I '
            'USING ( '
            '  tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid '
            '  OR current_setting(''app.is_platform_admin'', true) = ''true'' '
            ')',
            t || '_tenant_isolation', t
        );

        RAISE NOTICE 'rls shadow: policy installed on % (RLS not yet enabled)', t;
    END LOOP;
END $$;

-- NOTE intentionally no ALTER TABLE … ENABLE ROW LEVEL SECURITY in
-- this migration. Policies are inert until an operator runs the
-- follow-up migration. See docs/architecture/rls-rollout.md for the
-- procedure.

COMMENT ON SCHEMA public IS 'RLS policies defined in migration 000157 (shadow mode — policies created, RLS not enabled).';
