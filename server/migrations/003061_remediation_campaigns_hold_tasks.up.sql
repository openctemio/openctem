-- Remediation campaigns hold tasks, not findings
-- (docs/rfcs/RFC-098-remediation-tasks.md, "Campaigns").
--
-- A finding is in at most one active work unit: the primary membership of an
-- active remediation task. A campaign is a program of tasks
-- (remediation_tasks.campaign_id); it never holds findings itself. Until now a
-- campaign tracked findings through its finding_filter, evaluated on every
-- read. This migration turns what each running campaign tracks into tasks:
--
-- * Campaigns in draft, active, paused or validating are converted; completed
--   and canceled campaigns are history and keep no work.
-- * The filter is evaluated exactly as the API evaluated it: a fix key
--   (remediation_key) tracks its solution family (pentest findings excluded);
--   otherwise the filter needs a CVE, finding id, asset or tool to track
--   anything (severities, sources, statuses and search text only narrow it),
--   and a filter that does not parse tracks nothing. Only open findings move
--   (not closed ones, and not unpublished pentest drafts or findings in
--   review).
-- * A finding tracked by two campaigns goes to one: the campaign that is
--   furthest along (active or validating, then paused, then draft), and among
--   those the oldest. Work that started wins over a plan nobody started; among
--   equals, the first claim wins, as it does for every task claim since.
-- * A finding that is already the primary member of a task does not move. A
--   live task with no campaign joins the campaign (the best-ranked campaign
--   when its findings were claimed by several); a task in another campaign
--   stays there and the claim is recorded as a conflict.
-- * The other findings of a campaign become one new task under it: a manual
--   action, title = campaign name, owner = the campaign's assignee (when still
--   an active member) and team. The task takes no manual deadline: the
--   campaign's due date already bounds every task of the campaign and follows
--   the campaign when its due date changes.
--
-- Report: one audit row per converted campaign (action
-- remediation_campaign.migrated: outcome, findings moved, tasks attached,
-- every conflict up to 100 and their count, the original filter), a timeline
-- entry on each task that joined a campaign or kept findings another campaign
-- claimed, a remediation_task_changed entry on each moved finding, one notice
-- to the owners and admins of each organization concerned, and a summary in
-- the migration output. The unique index ux_remediation_task_members_primary
-- then holds the invariant: the conversion never inserts a second primary
-- membership, and a concurrent claim cannot slip in (membership writes are
-- locked for the few seconds it runs).
--
-- The conversion is a function so the API change that stops reading
-- finding_filter can run it once more, for campaigns created between this
-- migration and that release, and then drop it. Run twice, it changes nothing
-- the second time.
--
-- Live impact: reads findings once per running campaign (a handful of rows in
-- remediation_campaigns); writes one task per converted campaign and one
-- member and one finding timeline row per moved finding. remediation_campaigns
-- itself is not changed: finding_filter stays until the contract step drops it.
-- expand-contract-ok: nothing is dropped; the only DROP TABLE removes the conversion's own session temp tables (rcm_*)

CREATE OR REPLACE FUNCTION remediation_campaign_filter_parse(
    p_filter jsonb,
    OUT ok boolean,
    OUT scoped boolean,
    OUT fix_key text,
    OUT severities text[],
    OUT sources text[],
    OUT cve_ids text[],
    OUT finding_ids uuid[],
    OUT asset_id uuid,
    OUT tool_name text,
    OUT search_pattern text)
LANGUAGE plpgsql
IMMUTABLE
AS $fn$
DECLARE
    k      text;
    canon  text;
    seen   text[] := '{}';
    v      jsonb;
    vals   text[];
    uuid_re  constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
    blank_re constant text := '^\s*$';
BEGIN
    ok := false;
    scoped := false;
    IF p_filter IS NULL OR jsonb_typeof(p_filter) <> 'object' THEN
        RETURN;
    END IF;

    -- A fix key campaign was resolved through its key alone, whatever else
    -- the filter held.
    IF jsonb_typeof(p_filter -> 'remediation_key') = 'string' AND p_filter ->> 'remediation_key' <> '' THEN
        fix_key := p_filter ->> 'remediation_key';
        ok := true;
        scoped := true;
        RETURN;
    END IF;

    -- Strict parse: every key known and named once, every value parses.
    FOR k IN SELECT jsonb_object_keys(p_filter) LOOP
        canon := CASE k
            WHEN 'severities' THEN 'severities' WHEN 'severity' THEN 'severities'
            WHEN 'sources' THEN 'sources' WHEN 'source' THEN 'sources'
            WHEN 'statuses' THEN 'statuses' WHEN 'status' THEN 'statuses'
            WHEN 'cve_ids' THEN 'cve_ids' WHEN 'cve_id' THEN 'cve_ids'
            WHEN 'finding_ids' THEN 'finding_ids' WHEN 'finding_id' THEN 'finding_ids'
            WHEN 'asset_id' THEN 'asset_id'
            WHEN 'tool_name' THEN 'tool_name'
            WHEN 'search' THEN 'search'
            WHEN 'remediation_key' THEN 'remediation_key'
        END;
        IF canon IS NULL OR canon = ANY (seen) OR canon = 'remediation_key' THEN
            RETURN;
        END IF;
        seen := seen || canon;

        -- A non-empty string or a non-empty list (at most 2000) of non-empty strings.
        v := p_filter -> k;
        IF jsonb_typeof(v) = 'string' THEN
            IF (v #>> '{}') ~ blank_re THEN RETURN; END IF;
            vals := ARRAY[v #>> '{}'];
        ELSIF jsonb_typeof(v) = 'array' THEN
            IF jsonb_array_length(v) = 0 OR jsonb_array_length(v) > 2000 THEN RETURN; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(v) e
                        WHERE jsonb_typeof(e) <> 'string' OR (e #>> '{}') ~ blank_re) THEN
                RETURN;
            END IF;
            SELECT array_agg(e #>> '{}' ORDER BY n) INTO vals FROM jsonb_array_elements(v) WITH ORDINALITY AS x(e, n);
        ELSE
            RETURN;
        END IF;

        IF canon IN ('asset_id', 'tool_name', 'search')
           AND (cardinality(vals) <> 1 OR octet_length(vals[1]) > 255) THEN
            RETURN;
        END IF;

        CASE canon
        WHEN 'severities' THEN
            IF EXISTS (SELECT 1 FROM unnest(vals) s
                        WHERE lower(btrim(s)) NOT IN ('critical', 'high', 'medium', 'low', 'info', 'none')) THEN
                RETURN;
            END IF;
            severities := (SELECT array_agg(lower(btrim(s))) FROM unnest(vals) s);
        WHEN 'sources' THEN
            IF EXISTS (SELECT 1 FROM unnest(vals) s
                        WHERE lower(btrim(s)) NOT IN ('sast', 'dast', 'sca', 'secret', 'iac', 'container', 'cspm',
                            'easm', 'va', 'rasp', 'waf', 'siem', 'manual', 'pentest', 'bug_bounty', 'red_team',
                            'external', 'threat_intel', 'vendor', 'sarif', 'sca_tool')) THEN
                RETURN;
            END IF;
            sources := (SELECT array_agg(lower(btrim(s))) FROM unnest(vals) s);
        WHEN 'statuses' THEN
            -- Checked, then ignored: a campaign tracked its scope whatever the status.
            IF EXISTS (SELECT 1 FROM unnest(vals) s
                        WHERE s NOT IN ('new', 'confirmed', 'in_progress', 'fix_applied', 'resolved',
                            'false_positive', 'accepted', 'duplicate', 'draft', 'in_review')) THEN
                RETURN;
            END IF;
        WHEN 'cve_ids' THEN
            IF EXISTS (SELECT 1 FROM unnest(vals) s WHERE s !~ '^CVE-\d{4}-\d{4,}$') THEN RETURN; END IF;
            cve_ids := vals;
        WHEN 'finding_ids' THEN
            IF EXISTS (SELECT 1 FROM unnest(vals) s WHERE s !~ uuid_re) THEN RETURN; END IF;
            finding_ids := vals::uuid[];
        WHEN 'asset_id' THEN
            IF vals[1] !~ uuid_re THEN RETURN; END IF;
            asset_id := vals[1]::uuid;
        WHEN 'tool_name' THEN
            tool_name := vals[1];
        WHEN 'search' THEN
            search_pattern := '%' || replace(replace(replace(vals[1], '\', '\\'), '%', '\%'), '_', '\_') || '%';
        END CASE;
    END LOOP;

    ok := true;
    scoped := cve_ids IS NOT NULL OR finding_ids IS NOT NULL OR asset_id IS NOT NULL OR tool_name IS NOT NULL;
END;
$fn$;

COMMENT ON FUNCTION remediation_campaign_filter_parse(jsonb) IS
    'One-time conversion helper: a legacy campaign finding_filter parsed as the API parsed it (ok = parses, scoped = tracks findings). Dropped with remediation_campaigns_to_tasks.';

CREATE OR REPLACE FUNCTION remediation_campaigns_to_tasks(p_report_unchanged boolean)
RETURNS integer
LANGUAGE plpgsql
AS $fn$
DECLARE
    v_row     record;
    v_reported integer;
BEGIN
    -- No concurrent claim while the claims are computed and written.
    LOCK TABLE remediation_task_members IN SHARE ROW EXCLUSIVE MODE;

    DROP TABLE IF EXISTS rcm_campaign, rcm_scope, rcm_claim, rcm_held, rcm_attach, rcm_new, rcm_conflict, rcm_report;

    CREATE TEMP TABLE rcm_campaign ON COMMIT DROP AS
    SELECT c.id, c.tenant_id, c.name, c.status, c.created_at, c.finding_filter, c.due_date,
           CASE WHEN c.status IN ('active', 'validating') THEN 1 WHEN c.status = 'paused' THEN 2 ELSE 3 END AS rank,
           (SELECT u.id FROM users u WHERE u.id = c.created_by) AS created_by,
           (SELECT tm.user_id FROM tenant_members tm
             WHERE tm.tenant_id = c.tenant_id AND tm.user_id = c.assigned_to AND tm.status = 'active') AS assignee_user,
           (SELECT g.id FROM groups g WHERE g.tenant_id = c.tenant_id AND g.id = c.assigned_team) AS assignee_group,
           c.assigned_to, c.assigned_team,
           p.ok AS filter_ok, p.scoped AS filter_scoped, p.fix_key, p.severities, p.sources, p.cve_ids,
           p.finding_ids, p.asset_id, p.tool_name, p.search_pattern,
           NULL::uuid AS task_id, NULL::uuid AS action_id, false AS task_is_new
      FROM remediation_campaigns c
     CROSS JOIN LATERAL remediation_campaign_filter_parse(c.finding_filter) p
     WHERE c.status IN ('draft', 'active', 'paused', 'validating');

    -- What each campaign tracks today, open findings only.
    CREATE TEMP TABLE rcm_scope ON COMMIT DROP AS
    SELECT c.tenant_id, c.id AS campaign_id, f.id AS finding_id
      FROM rcm_campaign c
      JOIN findings f ON f.tenant_id = c.tenant_id
     WHERE c.filter_ok AND c.filter_scoped
       AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'draft', 'in_review')
       AND (c.fix_key IS NULL OR (f.source <> 'pentest' AND EXISTS (
                SELECT 1 FROM finding_remediation_keys k
                 WHERE k.tenant_id = f.tenant_id AND k.finding_id = f.id AND k.remediation_key = c.fix_key)))
       AND (c.severities IS NULL OR f.severity = ANY (c.severities))
       AND (c.sources IS NULL OR f.source = ANY (c.sources))
       AND (c.cve_ids IS NULL OR f.cve_id = ANY (c.cve_ids))
       AND (c.finding_ids IS NULL OR f.id = ANY (c.finding_ids))
       AND (c.asset_id IS NULL OR f.asset_id = c.asset_id)
       AND (c.tool_name IS NULL OR f.tool_name = c.tool_name)
       AND (c.search_pattern IS NULL OR f.title ILIKE c.search_pattern
            OR f.description ILIKE c.search_pattern OR f.file_path ILIKE c.search_pattern);

    -- One campaign per finding: furthest along, then oldest.
    CREATE TEMP TABLE rcm_claim ON COMMIT DROP AS
    SELECT DISTINCT ON (s.tenant_id, s.finding_id) s.tenant_id, s.finding_id, s.campaign_id
      FROM rcm_scope s
      JOIN rcm_campaign c ON c.id = s.campaign_id
     ORDER BY s.tenant_id, s.finding_id, c.rank, c.created_at, c.id;

    -- Claimed findings that are already the primary member of a task.
    CREATE TEMP TABLE rcm_held ON COMMIT DROP AS
    SELECT cl.tenant_id, cl.finding_id, cl.campaign_id, t.id AS task_id, t.campaign_id AS task_campaign,
           t.state IN ('open', 'in_progress', 'verifying', 'on_hold') AS task_live
      FROM rcm_claim cl
      JOIN remediation_task_members m
        ON m.tenant_id = cl.tenant_id AND m.finding_id = cl.finding_id AND m.left_at IS NULL AND m.role = 'primary'
      JOIN remediation_tasks t ON t.tenant_id = m.tenant_id AND t.id = m.task_id;

    -- Live tasks without a campaign join the best-ranked campaign that claimed one of their findings.
    CREATE TEMP TABLE rcm_attach ON COMMIT DROP AS
    SELECT DISTINCT ON (h.task_id) h.tenant_id, h.task_id, h.campaign_id
      FROM rcm_held h
      JOIN rcm_campaign c ON c.id = h.campaign_id
     WHERE h.task_campaign IS NULL AND h.task_live
     ORDER BY h.task_id, c.rank, c.created_at, c.id;

    -- The rest move into the campaign's task.
    CREATE TEMP TABLE rcm_new ON COMMIT DROP AS
    SELECT cl.tenant_id, cl.finding_id, cl.campaign_id
      FROM rcm_claim cl
     WHERE NOT EXISTS (SELECT 1 FROM rcm_held h WHERE h.tenant_id = cl.tenant_id AND h.finding_id = cl.finding_id);

    -- Every (campaign, finding) claim that did not end up under that campaign.
    CREATE TEMP TABLE rcm_conflict ON COMMIT DROP AS
    SELECT s.tenant_id, s.campaign_id, s.finding_id, 'claimed_by_campaign'::text AS reason,
           cl.campaign_id AS other_campaign_id, NULL::uuid AS task_id
      FROM rcm_scope s
      JOIN rcm_claim cl ON cl.tenant_id = s.tenant_id AND cl.finding_id = s.finding_id
     WHERE cl.campaign_id <> s.campaign_id
    UNION ALL
    SELECT h.tenant_id, h.campaign_id, h.finding_id,
           CASE WHEN h.task_live THEN 'task_in_other_campaign' ELSE 'task_closed' END,
           COALESCE(h.task_campaign, a.campaign_id), h.task_id
      FROM rcm_held h
      LEFT JOIN rcm_attach a ON a.task_id = h.task_id
     WHERE COALESCE(h.task_campaign, a.campaign_id) IS DISTINCT FROM h.campaign_id;

    -- The task each campaign's moved findings join: its earlier converted
    -- task while that one is still live (a second run), else a new one.
    UPDATE rcm_campaign c SET task_id = x.id
      FROM (SELECT DISTINCT ON (t.campaign_id) t.campaign_id, t.id
              FROM remediation_tasks t
             WHERE t.state IN ('open', 'in_progress', 'verifying', 'on_hold')
               AND EXISTS (SELECT 1 FROM remediation_task_events e
                            WHERE e.tenant_id = t.tenant_id AND e.task_id = t.id AND e.kind = 'created'
                              AND e.data ->> 'origin' = 'campaign_migration')
             ORDER BY t.campaign_id, t.created_at DESC) x
     WHERE x.campaign_id = c.id
       AND EXISTS (SELECT 1 FROM rcm_new n WHERE n.campaign_id = c.id);
    UPDATE rcm_campaign c SET task_id = uuid_generate_v7(), action_id = uuid_generate_v7(), task_is_new = true
     WHERE c.task_id IS NULL
       AND EXISTS (SELECT 1 FROM rcm_new n WHERE n.campaign_id = c.id);

    INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin, created_by)
    SELECT c.action_id, c.tenant_id, 'manual:' || c.task_id, 'manual',
           left(COALESCE(NULLIF(btrim(c.name), ''), 'Remediation campaign'), 300), 'manual', c.created_by
      FROM rcm_campaign c
     WHERE c.task_is_new;

    INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, assignee_user_id,
                                   assignee_group_id, created_by, recomputed_at)
    SELECT c.task_id, c.tenant_id, c.action_id, c.id,
           left(COALESCE(NULLIF(btrim(c.name), ''), 'Remediation campaign'), 300),
           c.assignee_user, c.assignee_group, c.created_by, 'epoch'
      FROM rcm_campaign c
     WHERE c.task_is_new;

    INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
    SELECT n.tenant_id, c.task_id, n.finding_id, 'primary', 'manual'
      FROM rcm_new n
      JOIN rcm_campaign c ON c.id = n.campaign_id;

    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
    SELECT n.tenant_id, n.finding_id, 'remediation_task_changed', 'system',
           jsonb_build_object('task_id', t.id, 'task_title', t.title, 'operation', 'joined', 'role', 'primary',
                              'campaign_id', c.id, 'origin', 'campaign_migration'),
           'remediation', format('Joined remediation task "%s"', t.title)
      FROM rcm_new n
      JOIN rcm_campaign c ON c.id = n.campaign_id
      JOIN remediation_tasks t ON t.tenant_id = c.tenant_id AND t.id = c.task_id;

    -- Counters, state and deadline of the new tasks (the remediation-tasks
    -- controller re-derives them too: recomputed_at is the epoch).
    WITH agg AS (
        SELECT m.task_id,
               count(*) AS total,
               count(*) FILTER (WHERE f.status = 'in_progress') AS in_progress,
               count(*) FILTER (WHERE f.status = 'fix_applied') AS fix_applied,
               COALESCE(sum(CASE f.priority_class
                   WHEN 'P0' THEN 8 WHEN 'P1' THEN 4 WHEN 'P2' THEN 2 WHEN 'P3' THEN 1
                   ELSE CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 WHEN 'low' THEN 1 ELSE 0 END
               END), 0) AS risk_points,
               min(f.sla_deadline) AS member_deadline
          FROM remediation_task_members m
          JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
         WHERE m.task_id IN (SELECT task_id FROM rcm_campaign WHERE task_is_new)
           AND m.left_at IS NULL AND m.role = 'primary'
         GROUP BY m.task_id
    ), dl AS (
        SELECT a.*, (c.due_date::timestamp AT TIME ZONE 'UTC') + interval '1 day' - interval '1 second' AS campaign_deadline
          FROM agg a
          JOIN rcm_campaign c ON c.task_id = a.task_id
    )
    UPDATE remediation_tasks t
       SET member_count = dl.total,
           open_count = dl.total - dl.in_progress - dl.fix_applied,
           in_progress_count = dl.in_progress,
           fix_applied_count = dl.fix_applied,
           risk_points = dl.risk_points,
           state = CASE WHEN dl.fix_applied > 0 AND dl.fix_applied >= dl.total THEN 'verifying'
                        WHEN dl.in_progress + dl.fix_applied > 0 THEN 'in_progress'
                        ELSE 'open' END,
           deadline = LEAST(dl.member_deadline, dl.campaign_deadline),
           deadline_source = CASE
               WHEN dl.member_deadline IS NOT NULL AND (dl.campaign_deadline IS NULL OR dl.member_deadline <= dl.campaign_deadline) THEN 'member'
               WHEN dl.campaign_deadline IS NOT NULL THEN 'campaign'
           END
      FROM dl
     WHERE t.id = dl.task_id;

    -- Earlier converted tasks that took more findings, and tasks that joined
    -- a campaign: the controller re-derives them (counters, campaign deadline).
    UPDATE remediation_tasks t
       SET version = t.version + 1, updated_at = now(), recomputed_at = 'epoch'
      FROM rcm_campaign c
     WHERE t.id = c.task_id AND NOT c.task_is_new;
    UPDATE remediation_tasks t
       SET campaign_id = a.campaign_id, version = t.version + 1, updated_at = now(), recomputed_at = 'epoch'
      FROM rcm_attach a
     WHERE t.tenant_id = a.tenant_id AND t.id = a.task_id AND t.campaign_id IS NULL;

    -- What changed per campaign, and what is reported.
    CREATE TEMP TABLE rcm_report ON COMMIT DROP AS
    SELECT c.id, c.tenant_id, c.name, c.task_id, c.task_is_new, c.finding_filter,
           (c.assigned_to IS NOT NULL AND c.assignee_user IS NULL)
               OR (c.assigned_team IS NOT NULL AND c.assignee_group IS NULL) AS assignee_dropped,
           (SELECT count(*) FROM rcm_new n WHERE n.campaign_id = c.id) AS moved,
           COALESCE((SELECT jsonb_agg(a.task_id ORDER BY a.task_id) FROM rcm_attach a WHERE a.campaign_id = c.id), '[]'::jsonb) AS attached,
           (SELECT count(*) FROM rcm_attach a WHERE a.campaign_id = c.id) AS attached_count,
           (SELECT count(*) FROM rcm_conflict x WHERE x.campaign_id = c.id) AS conflict_count,
           COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                         'finding_id', x.finding_id, 'reason', x.reason,
                         'campaign_id', x.other_campaign_id, 'task_id', x.task_id)) ORDER BY x.finding_id)
                       FROM (SELECT * FROM rcm_conflict x WHERE x.campaign_id = c.id ORDER BY x.finding_id LIMIT 100) x),
                    '[]'::jsonb) AS conflicts,
           CASE WHEN NOT c.filter_ok THEN 'invalid_filter'
                WHEN NOT c.filter_scoped THEN 'no_scope'
                WHEN EXISTS (SELECT 1 FROM rcm_new n WHERE n.campaign_id = c.id)
                  OR EXISTS (SELECT 1 FROM rcm_attach a WHERE a.campaign_id = c.id) THEN 'tasks'
                WHEN EXISTS (SELECT 1 FROM rcm_scope s WHERE s.campaign_id = c.id) THEN 'all_elsewhere'
                ELSE 'no_open_findings'
           END AS outcome
      FROM rcm_campaign c;
    DELETE FROM rcm_report r
     WHERE NOT p_report_unchanged AND r.moved = 0 AND r.attached_count = 0;

    -- Timeline of each task.
    INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_type, data)
    SELECT r.tenant_id, r.task_id, 'created', 'system',
           jsonb_build_object('title', t.title, 'members', r.moved, 'related', 0,
                              'campaign_id', r.id, 'origin', 'campaign_migration')
      FROM rcm_report r
      JOIN remediation_tasks t ON t.id = r.task_id
     WHERE r.task_is_new;
    INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_type, data)
    SELECT r.tenant_id, r.task_id, 'members_added', 'system',
           jsonb_build_object('count', r.moved, 'role', 'primary', 'source', 'manual', 'origin', 'campaign_migration')
      FROM rcm_report r
     WHERE r.task_id IS NOT NULL AND NOT r.task_is_new AND r.moved > 0;
    INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_type, data)
    SELECT a.tenant_id, a.task_id, 'updated', 'system',
           jsonb_build_object('campaign_id', a.campaign_id, 'origin', 'campaign_migration')
      FROM rcm_attach a;
    INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_type, data)
    SELECT x.tenant_id, x.task_id, 'campaign_conflict', 'system',
           jsonb_build_object('campaign_id', x.campaign_id, 'count', count(*),
                              'reason', min(x.reason), 'origin', 'campaign_migration')
      FROM rcm_conflict x
      JOIN rcm_report r ON r.id = x.campaign_id
     WHERE x.task_id IS NOT NULL
     GROUP BY x.tenant_id, x.task_id, x.campaign_id;

    -- One audit row per campaign.
    INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, resource_name, severity, message, metadata)
    SELECT r.tenant_id, 'remediation_campaign.migrated', 'remediation_campaign', r.id::text, r.name,
           CASE WHEN r.conflict_count > 0 OR r.outcome IN ('invalid_filter', 'no_scope', 'all_elsewhere') OR r.assignee_dropped
                THEN 'medium' ELSE 'low' END,
           CASE r.outcome
               WHEN 'tasks' THEN format('Campaign now holds tasks: %s finding(s) moved into its task, %s existing task(s) joined it, %s finding(s) stayed where they were',
                                        r.moved, r.attached_count, r.conflict_count)
               WHEN 'all_elsewhere' THEN format('Campaign holds no task: all %s of its open finding(s) belong to another campaign or task', r.conflict_count)
               WHEN 'no_open_findings' THEN 'Campaign holds no task: it tracked no open finding'
               WHEN 'no_scope' THEN 'Campaign holds no task: its filter named no CVE, finding, asset, tool or fix, so it tracked nothing; add tasks to it'
               ELSE 'Campaign holds no task: its filter did not parse, so it tracked nothing; add tasks to it'
           END,
           jsonb_build_object('source', 'migration', 'outcome', r.outcome, 'task_id', r.task_id,
                              'findings_moved', r.moved, 'tasks_attached', r.attached,
                              'conflict_count', r.conflict_count, 'conflicts', r.conflicts,
                              'assignee_dropped', r.assignee_dropped, 'finding_filter', r.finding_filter)
      FROM rcm_report r;

    -- One notice per organization to its owners and admins.
    INSERT INTO notifications (tenant_id, audience, audience_id, notification_type, title, body, severity, url)
    SELECT s.tenant_id, 'user', tm.user_id, 'system_alert',
           'Remediation campaigns now hold tasks',
           format('%s campaign(s) were converted: %s finding(s) moved into new campaign tasks and %s existing task(s) joined a campaign. ',
                  s.campaigns, s.moved, s.attached)
           || CASE WHEN s.conflicts > 0
                   THEN format('%s finding claim(s) stayed where they were (another campaign or task held them). ', s.conflicts)
                   ELSE '' END
           || CASE WHEN s.empty > 0
                   THEN format('%s campaign(s) tracked nothing and now hold no task: add tasks to them. ', s.empty)
                   ELSE '' END
           || 'Details per campaign: Audit log, action "remediation_campaign.migrated".',
           CASE WHEN s.conflicts > 0 OR s.empty > 0 THEN 'medium' ELSE 'info' END,
           '/remediation/campaigns'
      FROM (SELECT r.tenant_id, count(*) AS campaigns, sum(r.moved) AS moved, sum(r.attached_count) AS attached,
                   sum(r.conflict_count) AS conflicts,
                   count(*) FILTER (WHERE r.outcome IN ('no_scope', 'invalid_filter')) AS empty
              FROM rcm_report r GROUP BY r.tenant_id) s
      JOIN tenant_members tm ON tm.tenant_id = s.tenant_id AND tm.role IN ('owner', 'admin') AND tm.status = 'active';

    FOR v_row IN
        SELECT tenant_id, count(*) AS campaigns, sum(moved) AS moved, sum(attached_count) AS attached,
               sum(conflict_count) AS conflicts,
               count(*) FILTER (WHERE outcome IN ('no_scope', 'invalid_filter')) AS empty
          FROM rcm_report GROUP BY tenant_id ORDER BY tenant_id
    LOOP
        RAISE NOTICE 'campaigns to tasks: tenant % - % campaign(s), % finding(s) moved, % task(s) attached, % conflict(s), % campaign(s) tracked nothing',
            v_row.tenant_id, v_row.campaigns, v_row.moved, v_row.attached, v_row.conflicts, v_row.empty;
    END LOOP;

    SELECT count(*) INTO v_reported FROM rcm_report;
    RETURN v_reported;
END;
$fn$;

COMMENT ON FUNCTION remediation_campaigns_to_tasks(boolean) IS
    'One-time conversion: what each running legacy campaign tracks becomes tasks of the campaign (conflicts audited). Idempotent; p_report_unchanged = report campaigns where nothing changed. Dropped by the contract step.';

SELECT remediation_campaigns_to_tasks(true);
