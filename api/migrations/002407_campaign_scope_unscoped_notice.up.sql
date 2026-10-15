-- Report the campaigns that track nothing once a campaign's scope must name
-- what is fixed (an asset, CVEs, linked findings, a tool or a fix key): a
-- filter of only severities, sources, statuses or search text no longer
-- counts as scope. Read-only: it changes no row, it only lists them in the
-- migration output so an operator can give each one a real scope.
DO $$
DECLARE
    r record;
    n integer := 0;
BEGIN
    FOR r IN
        SELECT tenant_id, id, name
        FROM remediation_campaigns
        WHERE status NOT IN ('completed', 'canceled')
          AND finding_filter IS NOT NULL
          AND finding_filter <> '{}'::jsonb
          AND NOT (finding_filter ?| ARRAY['asset_id', 'cve_ids', 'cve_id', 'finding_ids', 'finding_id', 'tool_name', 'remediation_key'])
        ORDER BY tenant_id, created_at
    LOOP
        n := n + 1;
        RAISE NOTICE 'campaign scope: tenant % campaign % (%) has no asset, CVE, finding, tool or fix key and now tracks nothing', r.tenant_id, r.id, r.name;
    END LOOP;
    RAISE NOTICE 'campaign scope: % open campaign(s) need a real scope', n;
END $$;
