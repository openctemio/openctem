-- Same-issue links between findings (docs/architecture/deduplication.md,
-- "Same issue across tools").
--
-- Two findings that different tools (or rules) report for one issue, on a
-- strong signal that is not an identity (two engines flag one SAST line with
-- the same weakness; one secret value found in two files), are linked as the
-- same issue: shown as one group and counted once in the dashboard facts,
-- while each keeps its own status, SLA, ticket and task. A link never
-- changes a finding.
--
-- finding_link_keys: the server-computed keys candidates are found by
-- (indexed; never values a person can read back). finding_issue_links: one
-- row per (primary, member) pair; a group is a star around its primary (the
-- earliest-created finding when the group formed). A pair a person unlinked
-- keeps its row (state unlinked) and is never linked again automatically; a
-- pair whose signal no longer holds is released by the system.

CREATE TABLE IF NOT EXISTS finding_link_keys (
    tenant_id  uuid        NOT NULL,
    finding_id uuid        NOT NULL,
    kind       varchar(16) NOT NULL,
    key        char(64)    NOT NULL,
    start_line integer,
    end_line   integer,
    CONSTRAINT pk_finding_link_keys PRIMARY KEY (finding_id, kind, key),
    CONSTRAINT fk_finding_link_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_link_keys_finding FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_finding_link_keys_kind CHECK (kind IN ('sast_cwe', 'secret_value')),
    CONSTRAINT chk_finding_link_keys_key CHECK (key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_finding_link_keys_lines CHECK (start_line IS NULL OR (start_line >= 0 AND end_line >= start_line))
);
CREATE INDEX IF NOT EXISTS idx_finding_link_keys_lookup ON finding_link_keys (tenant_id, kind, key);
COMMENT ON TABLE finding_link_keys IS
    'Server-computed keys same-issue candidates are found by (one indexed lookup per ingest batch). sast_cwe: hash of asset, path and one CWE, with the line range; secret_value: hash of the per-tenant keyed hash of a raw secret. Never returned by the API.';

CREATE TABLE IF NOT EXISTS finding_issue_links (
    id          uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid        NOT NULL,
    primary_id  uuid        NOT NULL,
    member_id   uuid        NOT NULL,
    rule        varchar(24) NOT NULL,
    basis       text[]      NOT NULL DEFAULT '{}',
    state       varchar(16) NOT NULL DEFAULT 'active',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    ended_by    uuid,
    CONSTRAINT pk_finding_issue_links PRIMARY KEY (id),
    CONSTRAINT fk_finding_issue_links_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_issue_links_primary FOREIGN KEY (primary_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_issue_links_member FOREIGN KEY (member_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_finding_issue_links_ended_by FOREIGN KEY (ended_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_finding_issue_links_distinct CHECK (primary_id <> member_id),
    CONSTRAINT chk_finding_issue_links_rule CHECK (rule IN ('sast_overlap', 'secret_value', 'vuln_alias')),
    CONSTRAINT chk_finding_issue_links_state CHECK (state IN ('active', 'unlinked', 'released')),
    CONSTRAINT chk_finding_issue_links_basis CHECK (cardinality(basis) <= 8),
    CONSTRAINT chk_finding_issue_links_ended CHECK ((state = 'active') = (ended_at IS NULL))
);
-- A finding is a member of at most one group, and one row per pair.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_issue_links_active_member
    ON finding_issue_links (tenant_id, member_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_issue_links_pair
    ON finding_issue_links (tenant_id, primary_id, member_id);
CREATE INDEX IF NOT EXISTS idx_finding_issue_links_primary
    ON finding_issue_links (tenant_id, primary_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_finding_issue_links_member ON finding_issue_links (tenant_id, member_id);
COMMENT ON TABLE finding_issue_links IS
    'Same-issue links: a member and the primary of its group. Never changes either finding. state: active, unlinked (by a person, ended_by; never linked again automatically), released (the signal no longer holds). basis lists the field names the rule compared, never values.';

-- A link or unlink changes what the dashboard facts count: mark both assets.
CREATE OR REPLACE FUNCTION finding_issue_links_mark_dash() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM dash_mark_asset(f.tenant_id, f.asset_id, 1::smallint)
    FROM findings f
    WHERE f.tenant_id = NEW.tenant_id AND f.id IN (NEW.primary_id, NEW.member_id);
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION finding_issue_links_mark_dash() IS
    'Marks the assets of both findings of a same-issue link dirty for the dashboard facts when the link is made or ends.';

DROP TRIGGER IF EXISTS trg_finding_issue_links_mark_dash ON finding_issue_links;
CREATE TRIGGER trg_finding_issue_links_mark_dash
    AFTER INSERT OR UPDATE OF state, primary_id ON finding_issue_links
    FOR EACH ROW EXECUTE FUNCTION finding_issue_links_mark_dash();

-- Timeline entries for a link and an unlink. The list is read back from the
-- constraint and written again with the new values.
DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['issue_linked', 'issue_unlinked'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT vals @> added THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM (SELECT DISTINCT unnest(vals || added) AS v) u));
    END IF;
END;
$$;

-- The fact builder counts a same-issue group once per asset and state. No
-- rebuild is needed: no link exists yet.

-- Severity order for counting a group once (most severe first).
CREATE OR REPLACE FUNCTION dash_severity_rank(p_severity text) RETURNS smallint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE p_severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                           WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END::smallint
$$;
CREATE OR REPLACE FUNCTION dash_recompute_asset(p_tenant uuid, p_asset uuid) RETURNS integer
LANGUAGE plpgsql AS $$
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
$$;

COMMENT ON FUNCTION dash_recompute_asset(uuid, uuid) IS
    'Dashboard facts: recomputes F1, F2 (history window) and F3 of one asset from its findings, writing only differences; returns the number of fact rows changed. All-zero asset id = findings without an asset. Pentest findings without a campaign carry the all-f campaign id, which matches no membership. A same-issue group counts once per state.';
