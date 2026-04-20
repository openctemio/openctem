-- Drop the tenant-isolation policies installed by 000157.
-- Does not toggle RLS enable/disable — that belongs to the ops
-- migrations that enable it per-table.

DO $$
DECLARE
    t TEXT;
    tables TEXT[] := ARRAY[
        'assets', 'findings', 'exposures', 'finding_comments',
        'finding_approvals', 'finding_activity', 'asset_groups',
        'asset_relationships', 'components', 'iocs', 'ioc_matches',
        'runtime_telemetry_events', 'ctem_cycles', 'priority_class_audit_log',
        'compensating_controls', 'scans', 'pipelines', 'tool_executions',
        'audit_logs', 'notification_outbox'
    ];
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        IF EXISTS (
            SELECT 1 FROM pg_policies
             WHERE schemaname = 'public'
               AND tablename = t
               AND policyname = t || '_tenant_isolation'
        ) THEN
            EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        END IF;
    END LOOP;
END $$;
