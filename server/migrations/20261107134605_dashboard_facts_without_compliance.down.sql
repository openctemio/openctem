-- Restores the previous definitions (compliance counted in the facts).

CREATE OR REPLACE FUNCTION public.dash_recompute_asset(p_tenant uuid, p_asset uuid)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_none  constant uuid := '00000000-0000-0000-0000-000000000000';
    -- A pentest finding without a campaign: matches no campaign membership.
    v_nocamp constant uuid := 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    v_since date := dash_history_start();
    v_total integer;
BEGIN
    IF p_tenant IS NULL OR p_asset IS NULL THEN
        RAISE EXCEPTION 'dash_recompute_asset: tenant and asset are required';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('dash_facts:' || p_tenant::text || ':' || p_asset::text, 0));

    -- One statement: the asset's published findings (no draft/in_review, no
    -- branch-only) are read once and every fact table is diffed against them.
    WITH src AS MATERIALIZED (
        SELECT f.id, dash_finding_lens(f.status) AS lens, f.severity,
               COALESCE(f.priority_class, 'none') AS priority_class,
               dash_sla_state(f.sla_status) AS sla_state, f.sla_status, f.source,
               COALESCE(f.is_in_kev, false) AS kev, COALESCE(f.is_reachable, false) AS reachable,
               CASE WHEN f.source = 'pentest' THEN COALESCE(f.pentest_campaign_id, v_nocamp) ELSE v_none END AS campaign,
               f.epss_score AS epss, COALESCE(f.first_detected_at, f.created_at) AS first_detected,
               f.created_at, f.resolved_at, f.last_reopened_at, f.sla_deadline
        FROM findings f
        WHERE f.tenant_id = p_tenant
          AND ((p_asset = v_none AND f.asset_id IS NULL) OR f.asset_id = p_asset)
          AND NOT f.branch_only
          AND dash_finding_lens(f.status) IS NOT NULL
          -- A finding linked as the same issue as another finding of this
          -- asset in the same state is counted once: a member is left out
          -- when another finding of its group there is at least as severe
          -- and at least as urgent (the primary first, then the earliest),
          -- so counting once never hides a higher severity or priority.
          AND NOT EXISTS (
              SELECT 1
              FROM finding_issue_links l
              JOIN findings g ON g.tenant_id = l.tenant_id
               AND (g.id = l.primary_id
                    OR g.id IN (SELECT l2.member_id FROM finding_issue_links l2
                                WHERE l2.tenant_id = l.tenant_id AND l2.primary_id = l.primary_id
                                  AND l2.state = 'active'))
              WHERE l.tenant_id = p_tenant AND l.member_id = f.id AND l.state = 'active'
                AND g.id <> f.id
                AND g.asset_id IS NOT DISTINCT FROM f.asset_id
                AND NOT g.branch_only
                AND dash_finding_lens(g.status) = dash_finding_lens(f.status)
                AND dash_severity_rank(g.severity) <= dash_severity_rank(f.severity)
                AND COALESCE(g.priority_class, 'none') <= COALESCE(f.priority_class, 'none')
                AND (g.id = l.primary_id
                     OR (dash_severity_rank(g.severity), COALESCE(g.priority_class, 'none'), g.created_at, g.id)
                      < (dash_severity_rank(f.severity), COALESCE(f.priority_class, 'none'), f.created_at, f.id)))
    ),
    -- F1
    s_new AS (
        SELECT lens, severity, priority_class, sla_state, source, kev, reachable,
               dash_age_band(lens, first_detected) AS age_band, campaign,
               count(*)::integer AS finding_count, COALESCE(sum(epss), 0) AS epss_sum
        FROM src
        GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9
    ), s_del AS (
        DELETE FROM dash_asset_state s
        WHERE s.tenant_id = p_tenant AND s.asset_id = p_asset
          AND NOT EXISTS (SELECT 1 FROM s_new n
                          WHERE n.lens = s.lens AND n.severity = s.severity
                            AND n.priority_class = s.priority_class AND n.sla_state = s.sla_state
                            AND n.source = s.source AND n.kev = s.kev AND n.reachable = s.reachable
                            AND n.age_band = s.age_band AND n.campaign = s.pentest_campaign_id)
        RETURNING 1
    ), s_ups AS (
        INSERT INTO dash_asset_state AS s (tenant_id, asset_id, lens, severity, priority_class, sla_state,
            source, kev, reachable, age_band, pentest_campaign_id, finding_count, epss_sum)
        SELECT p_tenant, p_asset, lens, severity, priority_class, sla_state, source, kev, reachable,
               age_band, campaign, finding_count, epss_sum
        FROM s_new
        ON CONFLICT ON CONSTRAINT pk_dash_asset_state DO UPDATE
            SET finding_count = EXCLUDED.finding_count, epss_sum = EXCLUDED.epss_sum
            WHERE (s.finding_count, s.epss_sum) IS DISTINCT FROM (EXCLUDED.finding_count, EXCLUDED.epss_sum)
        RETURNING 1
    ),
    -- F2: events per finding and UTC day, inside the history window.
    ev AS (
        SELECT (first_detected AT TIME ZONE 'UTC')::date AS day, severity, priority_class, campaign,
               1 AS opened, 0 AS fixed, 0 AS disp, 0 AS reopened, 1 AS net, 0 AS in_sla, NULL::integer AS bucket
        FROM src
        UNION ALL
        -- Leaving the open count: on the close date or, with no close date,
        -- on the day it was opened (so it never counts as open).
        SELECT (COALESCE(resolved_at, first_detected) AT TIME ZONE 'UTC')::date, severity, priority_class, campaign,
               0,
               CASE WHEN lens = 'fixed' AND resolved_at IS NOT NULL THEN 1 ELSE 0 END,
               CASE WHEN lens = 'dispositioned' AND resolved_at IS NOT NULL THEN 1 ELSE 0 END,
               0, -1,
               CASE WHEN lens = 'fixed' AND resolved_at IS NOT NULL AND sla_deadline IS NOT NULL
                         AND sla_status = 'on_track' THEN 1 ELSE 0 END,
               CASE WHEN lens = 'fixed' AND resolved_at IS NOT NULL
                    THEN dash_fix_hours_bucket(GREATEST(EXTRACT(EPOCH FROM (resolved_at - first_detected)) / 3600.0, 0)) END
        FROM src
        WHERE lens <> 'open'
        UNION ALL
        SELECT (last_reopened_at AT TIME ZONE 'UTC')::date, severity, priority_class, campaign, 0, 0, 0, 1, 0, 0, NULL
        FROM src
        WHERE last_reopened_at IS NOT NULL
    ), d_new AS (
        SELECT day, severity, priority_class, campaign,
               sum(opened)::integer AS opened, sum(fixed)::integer AS fixed, sum(disp)::integer AS disp,
               sum(reopened)::integer AS reopened, sum(net)::integer AS net, sum(in_sla)::integer AS in_sla,
               ARRAY[count(*) FILTER (WHERE bucket = 0), count(*) FILTER (WHERE bucket = 1),
                     count(*) FILTER (WHERE bucket = 2), count(*) FILTER (WHERE bucket = 3),
                     count(*) FILTER (WHERE bucket = 4), count(*) FILTER (WHERE bucket = 5),
                     count(*) FILTER (WHERE bucket = 6), count(*) FILTER (WHERE bucket = 7),
                     count(*) FILTER (WHERE bucket = 8), count(*) FILTER (WHERE bucket = 9),
                     count(*) FILTER (WHERE bucket = 10), count(*) FILTER (WHERE bucket = 11)]::integer[] AS hist
        FROM ev
        WHERE day >= v_since
        GROUP BY day, severity, priority_class, campaign
        HAVING sum(opened) <> 0 OR sum(fixed) <> 0 OR sum(disp) <> 0 OR sum(reopened) <> 0 OR sum(net) <> 0
    ), d_del AS (
        DELETE FROM dash_asset_day s
        WHERE s.tenant_id = p_tenant AND s.asset_id = p_asset AND s.day >= v_since
          AND NOT EXISTS (SELECT 1 FROM d_new n
                          WHERE n.day = s.day AND n.severity = s.severity AND n.priority_class = s.priority_class
                            AND n.campaign = s.pentest_campaign_id)
        RETURNING 1
    ), d_ups AS (
        INSERT INTO dash_asset_day AS s (tenant_id, day, asset_id, severity, priority_class, pentest_campaign_id,
            opened, fixed, dispositioned, reopened, net_open_delta, fixed_within_sla, fix_hours_hist)
        SELECT p_tenant, day, p_asset, severity, priority_class, campaign, opened, fixed, disp, reopened, net, in_sla, hist
        FROM d_new
        ON CONFLICT ON CONSTRAINT pk_dash_asset_day DO UPDATE
            SET opened = EXCLUDED.opened, fixed = EXCLUDED.fixed, dispositioned = EXCLUDED.dispositioned,
                reopened = EXCLUDED.reopened, net_open_delta = EXCLUDED.net_open_delta,
                fixed_within_sla = EXCLUDED.fixed_within_sla, fix_hours_hist = EXCLUDED.fix_hours_hist
            WHERE (s.opened, s.fixed, s.dispositioned, s.reopened, s.net_open_delta, s.fixed_within_sla, s.fix_hours_hist)
                IS DISTINCT FROM (EXCLUDED.opened, EXCLUDED.fixed, EXCLUDED.dispositioned, EXCLUDED.reopened,
                                  EXCLUDED.net_open_delta, EXCLUDED.fixed_within_sla, EXCLUDED.fix_hours_hist)
        RETURNING 1
    ),
    -- F3: open P0-P2, top 10 per kind, ranked per partition (non-pentest, or
    -- one pentest campaign).
    r_base AS (
        SELECT * FROM src WHERE lens = 'open' AND priority_class IN ('P0', 'P1', 'P2')
    ), r_all AS (
        SELECT 'fix_next'::text AS kind, source = 'pentest' AS is_pentest, campaign, id, priority_class, severity,
               created_at AS sort_at,
               row_number() OVER (PARTITION BY source = 'pentest', campaign
                                  ORDER BY priority_class,
                                           CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                                                         WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END,
                                           created_at DESC, id) AS rn
        FROM r_base
        UNION ALL
        SELECT 'sla_due', source = 'pentest', campaign, id, priority_class, severity, sla_deadline,
               row_number() OVER (PARTITION BY source = 'pentest', campaign ORDER BY sla_deadline, id)
        FROM r_base WHERE sla_deadline IS NOT NULL
        UNION ALL
        SELECT 'oldest', source = 'pentest', campaign, id, priority_class, severity, first_detected,
               row_number() OVER (PARTITION BY source = 'pentest', campaign ORDER BY first_detected, id)
        FROM r_base
    ), r_new AS (
        SELECT kind, is_pentest, campaign, rn::smallint AS rank, id, priority_class, severity, sort_at
        FROM r_all WHERE rn <= 10
    ), r_del AS (
        DELETE FROM dash_asset_rank s
        WHERE s.tenant_id = p_tenant AND s.asset_id = p_asset
          AND NOT EXISTS (SELECT 1 FROM r_new n
                          WHERE n.kind = s.kind AND n.is_pentest = s.is_pentest
                            AND n.campaign = s.pentest_campaign_id AND n.rank = s.rank)
        RETURNING 1
    ), r_ups AS (
        INSERT INTO dash_asset_rank AS s (tenant_id, asset_id, kind, is_pentest, pentest_campaign_id, rank,
            finding_id, priority_class, severity, sort_at)
        SELECT p_tenant, p_asset, kind, is_pentest, campaign, rank, id, priority_class, severity, sort_at
        FROM r_new
        ON CONFLICT ON CONSTRAINT pk_dash_asset_rank DO UPDATE
            SET finding_id = EXCLUDED.finding_id, priority_class = EXCLUDED.priority_class,
                severity = EXCLUDED.severity, sort_at = EXCLUDED.sort_at
            WHERE (s.finding_id, s.priority_class, s.severity, s.sort_at)
                IS DISTINCT FROM (EXCLUDED.finding_id, EXCLUDED.priority_class, EXCLUDED.severity, EXCLUDED.sort_at)
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM s_del) + (SELECT count(*) FROM s_ups)
         + (SELECT count(*) FROM d_del) + (SELECT count(*) FROM d_ups)
         + (SELECT count(*) FROM r_del) + (SELECT count(*) FROM r_ups)
    INTO v_total;
    RETURN v_total;
END;
$function$;

CREATE OR REPLACE FUNCTION public.dash_mark_from_finding_update()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
    SELECT c.tenant_id, c.asset_id, 1
    FROM (
        SELECT DISTINCT x.tenant_id, COALESCE(x.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) AS asset_id
        FROM new_rows n
        JOIN old_rows o ON o.id = n.id
        CROSS JOIN LATERAL (VALUES (n.tenant_id, n.asset_id), (o.tenant_id, o.asset_id)) x(tenant_id, asset_id)
        WHERE (o.status, o.severity, o.priority_class, o.sla_status, o.sla_deadline, o.source, o.is_in_kev,
               o.is_reachable, o.first_detected_at, o.pentest_campaign_id, o.asset_id, o.branch_only,
               o.epss_score, o.resolved_at, o.last_reopened_at, o.tenant_id)
              IS DISTINCT FROM
              (n.status, n.severity, n.priority_class, n.sla_status, n.sla_deadline, n.source, n.is_in_kev,
               n.is_reachable, n.first_detected_at, n.pentest_campaign_id, n.asset_id, n.branch_only,
               n.epss_score, n.resolved_at, n.last_reopened_at, n.tenant_id)
    ) c
    WHERE EXISTS (SELECT 1 FROM tenants t WHERE t.id = c.tenant_id)
      AND NOT EXISTS (
        SELECT 1 FROM dash_dirty_assets d
        WHERE d.tenant_id = c.tenant_id AND d.asset_id = c.asset_id AND d.reasons & 1 = 1
        LIMIT 1
        FOR KEY SHARE SKIP LOCKED)
    ORDER BY c.tenant_id, c.asset_id;
    RETURN NULL;
END;
$function$;
