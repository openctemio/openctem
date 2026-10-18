-- Dashboard fact layer (api/docs/architecture/dashboards.md, "Fact layer").
--
-- Dashboards will read stored per-asset facts instead of aggregating the
-- findings table on every open. Facts are per asset so that any viewer scope
-- (user_accessible_assets) or published scope (asset groups) applies as a join.
--
--   dash_asset_state  F1  current counts per asset and dimension combination
--   dash_asset_day    F2  per asset and day: opened, fixed, dispositioned, ...
--                         (monthly partitions on day)
--   dash_asset_rank   F3  per asset: top 10 open P0-P2 findings per list kind
--   dash_dirty_assets     assets whose facts must be recomputed
--   dash_fact_status      per tenant: last full rebuild, age-band marking
--
-- Every fact is a pure function of the asset's current findings, computed by
-- dash_recompute_asset. Triggers on findings, assets, asset_group_members and
-- asset_owners only append (tenant, asset, reason) to dash_dirty_assets; the
-- facts maintainer claims those rows and recomputes. No aggregation runs
-- inside a trigger.
--
-- Facts hold ids, never names or text. Pentest draft and in_review findings
-- are never stored; pentest findings carry their campaign id so a read can
-- apply the campaign membership rule or leave them out. Findings without an
-- asset are stored under the all-zero asset id, which never matches an asset,
-- a group or a viewer's scope.
--
-- Live impact: new tables, functions and triggers only; no rewrite and no
-- backfill here (the facts maintainer builds each tenant with
-- dash_rebuild_tenant_batch). The findings triggers add one small insert per
-- statement and changed asset.

-- ---------------------------------------------------------------------------
-- Helpers: the definitions every recompute and every reader share.
-- ---------------------------------------------------------------------------

-- The findings state lens (pkg/domain/vulnerability/finding_lens.go). NULL for
-- a status outside every lens (pentest draft and in_review), which is not
-- stored.
CREATE OR REPLACE FUNCTION dash_finding_lens(p_status text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN p_status IN ('new', 'confirmed', 'in_progress', 'fix_applied') THEN 'open'
        WHEN p_status = 'resolved' THEN 'fixed'
        WHEN p_status IN ('false_positive', 'accepted', 'duplicate') THEN 'dispositioned'
    END
$$;
COMMENT ON FUNCTION dash_finding_lens(text) IS
    'Dashboard facts: the state lens of a finding status (open, fixed, dispositioned), NULL when not stored (draft, in_review).';

-- findings.sla_status folded to four states. On a fixed finding "ok" means
-- fixed within the SLA and "breached" fixed late.
CREATE OR REPLACE FUNCTION dash_sla_state(p_sla_status text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE p_sla_status
        WHEN 'on_track' THEN 'ok'
        WHEN 'warning' THEN 'warning'
        WHEN 'overdue' THEN 'breached'
        WHEN 'exceeded' THEN 'breached'
        ELSE 'none'
    END
$$;
COMMENT ON FUNCTION dash_sla_state(text) IS
    'Dashboard facts: findings.sla_status folded to ok, warning, breached or none.';

-- Age band of an open finding from its first detection, at the time of the
-- recompute: 0-30, 31-60, 61-90 or 90+ whole days. Closed findings get "na".
-- The band moves with time alone; dash_mark_aged_assets marks the assets
-- whose findings crossed a boundary.
CREATE OR REPLACE FUNCTION dash_age_band(p_lens text, p_first_detected timestamptz) RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN p_lens IS DISTINCT FROM 'open' THEN 'na'
        WHEN p_first_detected IS NULL OR p_first_detected > now() - interval '31 days' THEN '0-30'
        WHEN p_first_detected > now() - interval '61 days' THEN '31-60'
        WHEN p_first_detected > now() - interval '91 days' THEN '61-90'
        ELSE '90+'
    END
$$;
COMMENT ON FUNCTION dash_age_band(text, timestamptz) IS
    'Dashboard facts: age band of an open finding (0-30, 31-60, 61-90, 90+ days since first detection), na when not open.';

-- Bucket of a fix time in hours on a log2 scale: 0 = under 1 h, 1 = 1-2 h,
-- 2 = 2-4 h, ... 10 = 512-1024 h, 11 = 1024 h and more. Medians and p90 read
-- from these histograms are approximate.
CREATE OR REPLACE FUNCTION dash_fix_hours_bucket(p_hours double precision) RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN p_hours IS NULL OR p_hours < 1 THEN 0
        ELSE LEAST(11, floor(log(2.0, p_hours::numeric))::integer + 1)
    END
$$;
COMMENT ON FUNCTION dash_fix_hours_bucket(double precision) IS
    'Dashboard facts: log2 bucket (0..11) of a fix time in hours for dash_asset_day.fix_hours_hist.';

-- ---------------------------------------------------------------------------
-- F1: current state per asset.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dash_asset_state (
    tenant_id           uuid        NOT NULL,
    asset_id            uuid        NOT NULL,
    lens                varchar(16) NOT NULL,
    severity            varchar(20) NOT NULL,
    priority_class      varchar(4)  NOT NULL,
    sla_state           varchar(10) NOT NULL,
    source              varchar(20) NOT NULL,
    kev                 boolean     NOT NULL,
    reachable           boolean     NOT NULL,
    age_band            varchar(8)  NOT NULL,
    pentest_campaign_id uuid        NOT NULL,
    finding_count       integer     NOT NULL,
    epss_sum            numeric(14,5) NOT NULL DEFAULT 0,
    CONSTRAINT pk_dash_asset_state PRIMARY KEY (tenant_id, asset_id, lens, severity, priority_class,
        sla_state, source, kev, reachable, age_band, pentest_campaign_id),
    CONSTRAINT fk_dash_asset_state_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_asset_state_lens CHECK (lens IN ('open', 'fixed', 'dispositioned')),
    CONSTRAINT chk_dash_asset_state_priority CHECK (priority_class IN ('P0', 'P1', 'P2', 'P3', 'none')),
    CONSTRAINT chk_dash_asset_state_sla CHECK (sla_state IN ('ok', 'warning', 'breached', 'none')),
    CONSTRAINT chk_dash_asset_state_age CHECK (age_band IN ('0-30', '31-60', '61-90', '90+', 'na')),
    CONSTRAINT chk_dash_asset_state_count CHECK (finding_count > 0)
);
COMMENT ON TABLE dash_asset_state IS
    'Dashboard fact F1: published findings (no draft/in_review, no branch-only) per asset and dimension combination. priority_class none = unclassified; pentest_campaign_id is the all-zero id unless source is pentest; asset_id all-zero = findings without an asset.';

CREATE INDEX IF NOT EXISTS idx_dash_asset_state_lens
    ON dash_asset_state (tenant_id, lens, priority_class) INCLUDE (finding_count);

-- ---------------------------------------------------------------------------
-- F2: per asset per day, monthly partitions on day.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dash_asset_day (
    tenant_id        uuid        NOT NULL,
    day              date        NOT NULL,
    asset_id         uuid        NOT NULL,
    severity         varchar(20) NOT NULL,
    priority_class   varchar(4)  NOT NULL,
    pentest_campaign_id uuid     NOT NULL,
    opened           integer     NOT NULL DEFAULT 0,
    fixed            integer     NOT NULL DEFAULT 0,
    dispositioned    integer     NOT NULL DEFAULT 0,
    reopened         integer     NOT NULL DEFAULT 0,
    net_open_delta   integer     NOT NULL DEFAULT 0,
    fixed_within_sla integer     NOT NULL DEFAULT 0,
    fix_hours_hist   integer[]   NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0}',
    CONSTRAINT pk_dash_asset_day PRIMARY KEY (tenant_id, day, asset_id, severity, priority_class, pentest_campaign_id),
    CONSTRAINT fk_dash_asset_day_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_asset_day_priority CHECK (priority_class IN ('P0', 'P1', 'P2', 'P3', 'none')),
    CONSTRAINT chk_dash_asset_day_hist CHECK (cardinality(fix_hours_hist) = 12)
) PARTITION BY RANGE (day);
COMMENT ON TABLE dash_asset_day IS
    'Dashboard fact F2: per asset and UTC day, findings opened (first detected), fixed, dispositioned (resolved_at), reopened (last_reopened_at), net change of the open count, fixed within SLA, and a log2 histogram of fix hours. pentest_campaign_id as in F1 (all-zero unless source is pentest), so a trend applies the same campaign rule as the current counts. Derived from finding timestamps with current dimensions; monthly partitions.';

CREATE INDEX IF NOT EXISTS idx_dash_asset_day_asset ON dash_asset_day (tenant_id, asset_id, day);

-- Days outside every monthly partition land here.
CREATE TABLE IF NOT EXISTS dash_asset_day_default PARTITION OF dash_asset_day DEFAULT;

-- Creates the monthly partitions from the month of from_month for months
-- months; existing ones are kept. Called by migrations (the migrator owns the
-- schema); a later migration extends the months before they run out.
CREATE OR REPLACE FUNCTION dash_asset_day_ensure_partitions(from_month date, months integer)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    m       date := date_trunc('month', from_month)::date;
    created integer := 0;
    part    text;
BEGIN
    FOR i IN 0 .. GREATEST(months, 1) - 1 LOOP
        part := 'dash_asset_day_' || to_char(m, 'YYYY_MM');
        IF to_regclass(part) IS NULL THEN
            EXECUTE format('CREATE TABLE %I PARTITION OF dash_asset_day FOR VALUES FROM (%L) TO (%L)',
                           part, m, (m + interval '1 month')::date);
            created := created + 1;
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
    RETURN created;
END;
$$;
COMMENT ON FUNCTION dash_asset_day_ensure_partitions(date, integer) IS
    'Creates the monthly partitions of dash_asset_day from from_month for months months; returns how many were created.';

-- The kept history (13 months) through the next two years.
SELECT dash_asset_day_ensure_partitions((now() - interval '13 months')::date, 38);

-- First day of the history window that recomputes derive (13 whole months).
CREATE OR REPLACE FUNCTION dash_history_start() RETURNS date
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT (date_trunc('month', (now() AT TIME ZONE 'UTC')) - interval '13 months')::date
$$;
COMMENT ON FUNCTION dash_history_start() IS
    'Dashboard facts: first UTC day of the dash_asset_day window a recompute derives (start of the month 13 months ago).';

-- ---------------------------------------------------------------------------
-- F3: top 10 open P0-P2 findings per asset and list kind.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dash_asset_rank (
    tenant_id           uuid        NOT NULL,
    asset_id            uuid        NOT NULL,
    kind                varchar(16) NOT NULL,
    is_pentest          boolean     NOT NULL,
    pentest_campaign_id uuid        NOT NULL,
    rank                smallint    NOT NULL,
    finding_id          uuid        NOT NULL,
    priority_class      varchar(4)  NOT NULL,
    severity            varchar(20) NOT NULL,
    sort_at             timestamptz,
    CONSTRAINT pk_dash_asset_rank PRIMARY KEY (tenant_id, asset_id, kind, is_pentest, pentest_campaign_id, rank),
    CONSTRAINT fk_dash_asset_rank_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_asset_rank_kind CHECK (kind IN ('fix_next', 'sla_due', 'oldest')),
    CONSTRAINT chk_dash_asset_rank_rank CHECK (rank BETWEEN 1 AND 10)
);
COMMENT ON TABLE dash_asset_rank IS
    'Dashboard fact F3: per asset, the top 10 open P0-P2 findings per list kind (fix_next: priority, severity, newest; sla_due: earliest SLA deadline; oldest: first detected). Ranked separately for non-pentest findings and per pentest campaign, so a list stays exact after the campaign rule.';

CREATE INDEX IF NOT EXISTS idx_dash_asset_rank_kind ON dash_asset_rank (tenant_id, kind, asset_id, rank);

-- ---------------------------------------------------------------------------
-- Dirty queue.
-- ---------------------------------------------------------------------------
-- Append-only. A writer adds a row unless an unclaimed row for the same
-- (tenant, asset) with the same reasons already exists, which it then holds
-- with FOR KEY SHARE until it commits. The maintainer claims rows with
-- FOR UPDATE SKIP LOCKED, so it never claims a row a still-running writer
-- holds, and a writer never relies on a row the maintainer already claimed
-- (it adds a new one). No mark is lost, no writer waits, and the queue stays
-- near one row per dirty asset.
CREATE TABLE IF NOT EXISTS dash_dirty_assets (
    id        bigint      GENERATED ALWAYS AS IDENTITY,
    tenant_id uuid        NOT NULL,
    asset_id  uuid        NOT NULL,
    reasons   smallint    NOT NULL,
    marked_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_dash_dirty_assets PRIMARY KEY (id),
    CONSTRAINT fk_dash_dirty_assets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_dirty_assets_reasons CHECK (reasons > 0)
);
COMMENT ON TABLE dash_dirty_assets IS
    'Dashboard facts: assets to recompute. reasons bits: 1 findings changed, 2 asset row changed (insert, delete, watched attribute), 4 asset group membership, 8 asset ownership, 16 an open finding crossed an age band. asset_id all-zero = findings without an asset. Several rows per asset may exist; the maintainer ORs them.';

CREATE INDEX IF NOT EXISTS idx_dash_dirty_assets_asset ON dash_dirty_assets (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_dash_dirty_assets_claim ON dash_dirty_assets (tenant_id, id);

-- ---------------------------------------------------------------------------
-- Per-tenant fact status.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dash_fact_status (
    tenant_id     uuid        NOT NULL,
    rebuilt_at    timestamptz,
    aged_marked_at timestamptz,
    CONSTRAINT pk_dash_fact_status PRIMARY KEY (tenant_id),
    CONSTRAINT fk_dash_fact_status_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
COMMENT ON TABLE dash_fact_status IS
    'Dashboard facts per tenant: rebuilt_at = last completed full rebuild (NULL = facts not built yet); aged_marked_at = upper bound of the last dash_mark_aged_assets run.';

-- ---------------------------------------------------------------------------
-- Change marking. Each function appends the distinct (tenant, asset) pairs
-- of the change, ordered for a stable lock order.
--
-- A mark must never fail the write that caused it. The only constraint a
-- mark can violate is the tenant foreign key, when the write is the cascade
-- of a tenant delete (the tenant row is already gone in that transaction),
-- so a mark is skipped when its tenant no longer exists: the cascade removes
-- every fact of that tenant anyway. No EXCEPTION block: it would open a
-- subtransaction per statement on the hottest write path.
-- ---------------------------------------------------------------------------

-- Statement trigger over a findings transition table named changed_rows.
CREATE OR REPLACE FUNCTION dash_mark_from_finding_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
    SELECT c.tenant_id, c.asset_id, 1
    FROM (SELECT DISTINCT r.tenant_id,
                 COALESCE(r.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) AS asset_id
          FROM changed_rows r) c
    WHERE EXISTS (SELECT 1 FROM tenants t WHERE t.id = c.tenant_id)
      AND NOT EXISTS (
        SELECT 1 FROM dash_dirty_assets d
        WHERE d.tenant_id = c.tenant_id AND d.asset_id = c.asset_id AND d.reasons & 1 = 1
        LIMIT 1
        FOR KEY SHARE SKIP LOCKED)
    ORDER BY c.tenant_id, c.asset_id;
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION dash_mark_from_finding_rows() IS
    'Statement trigger: marks the distinct (tenant, asset) of the inserted or deleted findings dirty for the dashboard facts.';

-- Marks one (tenant, asset) with a reason. Used by the row triggers.
CREATE OR REPLACE FUNCTION dash_mark_asset(p_tenant uuid, p_asset uuid, p_reason smallint) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_asset uuid := COALESCE(p_asset, '00000000-0000-0000-0000-000000000000'::uuid);
BEGIN
    IF p_tenant IS NULL OR NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = p_tenant) THEN
        RETURN;
    END IF;
    PERFORM 1 FROM dash_dirty_assets d
    WHERE d.tenant_id = p_tenant AND d.asset_id = v_asset AND d.reasons & p_reason = p_reason
    LIMIT 1
    FOR KEY SHARE SKIP LOCKED;
    IF NOT FOUND THEN
        INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons) VALUES (p_tenant, v_asset, p_reason);
    END IF;
END;
$$;
COMMENT ON FUNCTION dash_mark_asset(uuid, uuid, smallint) IS
    'Marks one (tenant, asset) dirty for the dashboard facts with a reason bit, unless an unclaimed row already covers it.';

-- Statement trigger for findings updates, over the transition tables
-- old_rows and new_rows: marks the asset of every finding whose fact inputs
-- changed, and the previous asset of a finding that moved. A statement
-- trigger with transition tables cannot be limited to columns, so the
-- comparison happens here; an update that changes no input (a re-sighting
-- moving last_seen_at) inserts nothing.
CREATE OR REPLACE FUNCTION dash_mark_from_finding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
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
$$;
COMMENT ON FUNCTION dash_mark_from_finding_update() IS
    'Statement trigger: marks the (tenant, asset), and the previous asset of a moved finding, of findings whose dashboard fact inputs changed.';

-- Statement trigger over an assets transition table named changed_rows.
CREATE OR REPLACE FUNCTION dash_mark_from_asset_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
    SELECT c.tenant_id, c.id, 2
    FROM (SELECT DISTINCT r.tenant_id, r.id FROM changed_rows r WHERE r.tenant_id IS NOT NULL) c
    WHERE EXISTS (SELECT 1 FROM tenants t WHERE t.id = c.tenant_id)
      AND NOT EXISTS (
        SELECT 1 FROM dash_dirty_assets d
        WHERE d.tenant_id = c.tenant_id AND d.asset_id = c.id AND d.reasons & 2 = 2
        LIMIT 1
        FOR KEY SHARE SKIP LOCKED)
    ORDER BY c.tenant_id, c.id;
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION dash_mark_from_asset_rows() IS
    'Statement trigger: marks inserted or deleted assets dirty for the dashboard facts (reason 2).';

CREATE OR REPLACE FUNCTION dash_mark_asset_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM dash_mark_asset(NEW.tenant_id, NEW.id, 2::smallint);
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION dash_mark_asset_update() IS
    'Row trigger: marks an asset whose dashboard-relevant attributes changed (reason 2).';

-- Statement trigger over a membership transition table named changed_rows
-- with an asset_id column (asset_group_members, asset_owners). These tables
-- carry no tenant, so it comes from the asset. TG_ARGV[0] is the reason bit.
CREATE OR REPLACE FUNCTION dash_mark_from_member_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_reason smallint := TG_ARGV[0]::smallint;
BEGIN
    INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
    SELECT c.tenant_id, c.id, v_reason
    FROM (SELECT DISTINCT a.tenant_id, a.id
          FROM changed_rows r
          JOIN assets a ON a.id = r.asset_id
          WHERE a.tenant_id IS NOT NULL) c
    WHERE EXISTS (SELECT 1 FROM tenants t WHERE t.id = c.tenant_id)
      AND NOT EXISTS (
        SELECT 1 FROM dash_dirty_assets d
        WHERE d.tenant_id = c.tenant_id AND d.asset_id = c.id AND d.reasons & v_reason = v_reason
        LIMIT 1
        FOR KEY SHARE SKIP LOCKED)
    ORDER BY c.tenant_id, c.id;
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION dash_mark_from_member_rows() IS
    'Statement trigger: marks the assets of changed group-membership or ownership rows dirty for the dashboard facts (reason in TG_ARGV[0]).';

-- findings: every insert and delete; an update marks only the findings
-- whose fact inputs changed (a re-sighting that only moves last_seen_at
-- marks nothing). All three are statement triggers: one insert per
-- statement and asset, however many rows the statement changed.
DROP TRIGGER IF EXISTS trg_findings_dash_insert ON findings;
CREATE TRIGGER trg_findings_dash_insert
    AFTER INSERT ON findings
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_finding_rows();

DROP TRIGGER IF EXISTS trg_findings_dash_delete ON findings;
CREATE TRIGGER trg_findings_dash_delete
    AFTER DELETE ON findings
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_finding_rows();

DROP TRIGGER IF EXISTS trg_findings_dash_update ON findings;
CREATE TRIGGER trg_findings_dash_update
    AFTER UPDATE ON findings
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_finding_update();

-- assets: insert, delete, and the attributes dashboards group or filter by.
-- risk_score and last_seen are not watched (workers write them constantly).
DROP TRIGGER IF EXISTS trg_assets_dash_insert ON assets;
CREATE TRIGGER trg_assets_dash_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_asset_rows();

DROP TRIGGER IF EXISTS trg_assets_dash_delete ON assets;
CREATE TRIGGER trg_assets_dash_delete
    AFTER DELETE ON assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_asset_rows();

DROP TRIGGER IF EXISTS trg_assets_dash_update ON assets;
CREATE TRIGGER trg_assets_dash_update
    AFTER UPDATE OF asset_type, criticality, status, is_crown_jewel, exposure, is_internet_accessible,
        deleted_at, program_only, environment ON assets
    FOR EACH ROW
    WHEN (OLD.asset_type IS DISTINCT FROM NEW.asset_type
       OR OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.status IS DISTINCT FROM NEW.status
       OR OLD.is_crown_jewel IS DISTINCT FROM NEW.is_crown_jewel
       OR OLD.exposure IS DISTINCT FROM NEW.exposure
       OR OLD.is_internet_accessible IS DISTINCT FROM NEW.is_internet_accessible
       OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR OLD.program_only IS DISTINCT FROM NEW.program_only
       OR OLD.environment IS DISTINCT FROM NEW.environment)
    EXECUTE FUNCTION dash_mark_asset_update();

-- Group membership (published asset-group scopes) and ownership (viewer
-- scopes): every insert, delete and update.
DROP TRIGGER IF EXISTS trg_asset_group_members_dash_insert ON asset_group_members;
CREATE TRIGGER trg_asset_group_members_dash_insert
    AFTER INSERT ON asset_group_members
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('4');

DROP TRIGGER IF EXISTS trg_asset_group_members_dash_delete ON asset_group_members;
CREATE TRIGGER trg_asset_group_members_dash_delete
    AFTER DELETE ON asset_group_members
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('4');

DROP TRIGGER IF EXISTS trg_asset_group_members_dash_update_new ON asset_group_members;
CREATE TRIGGER trg_asset_group_members_dash_update_new
    AFTER UPDATE ON asset_group_members
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('4');

DROP TRIGGER IF EXISTS trg_asset_group_members_dash_update_old ON asset_group_members;
CREATE TRIGGER trg_asset_group_members_dash_update_old
    AFTER UPDATE ON asset_group_members
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('4');

DROP TRIGGER IF EXISTS trg_asset_owners_dash_insert ON asset_owners;
CREATE TRIGGER trg_asset_owners_dash_insert
    AFTER INSERT ON asset_owners
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('8');

DROP TRIGGER IF EXISTS trg_asset_owners_dash_delete ON asset_owners;
CREATE TRIGGER trg_asset_owners_dash_delete
    AFTER DELETE ON asset_owners
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('8');

DROP TRIGGER IF EXISTS trg_asset_owners_dash_update_new ON asset_owners;
CREATE TRIGGER trg_asset_owners_dash_update_new
    AFTER UPDATE ON asset_owners
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('8');

DROP TRIGGER IF EXISTS trg_asset_owners_dash_update_old ON asset_owners;
CREATE TRIGGER trg_asset_owners_dash_update_old
    AFTER UPDATE ON asset_owners
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION dash_mark_from_member_rows('8');

-- ---------------------------------------------------------------------------
-- Recompute.
-- ---------------------------------------------------------------------------

-- Recomputes F1, F2 (the history window) and F3 of one asset from its
-- current findings and writes only the differences. The all-zero asset id
-- recomputes the tenant's findings without an asset. Serialised per asset by
-- a transaction advisory lock; touches only that asset's fact rows.
-- Returns the number of fact rows inserted, updated or deleted.
CREATE OR REPLACE FUNCTION dash_recompute_asset(p_tenant uuid, p_asset uuid) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_none  constant uuid := '00000000-0000-0000-0000-000000000000';
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
               CASE WHEN f.source = 'pentest' THEN COALESCE(f.pentest_campaign_id, v_none) ELSE v_none END AS campaign,
               f.epss_score AS epss, COALESCE(f.first_detected_at, f.created_at) AS first_detected,
               f.created_at, f.resolved_at, f.last_reopened_at, f.sla_deadline
        FROM findings f
        WHERE f.tenant_id = p_tenant
          AND ((p_asset = v_none AND f.asset_id IS NULL) OR f.asset_id = p_asset)
          AND NOT f.branch_only
          AND dash_finding_lens(f.status) IS NOT NULL
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
    'Dashboard facts: recomputes F1, F2 (history window) and F3 of one asset from its findings, writing only differences; returns the number of fact rows changed. All-zero asset id = findings without an asset.';

-- One batch of a tenant's full rebuild: recomputes the next p_limit assets
-- after p_after (by id), so each call is a short transaction and the caller
-- commits between calls. Returns the last asset id processed, or NULL when
-- the rebuild is complete; the final call also recomputes the findings
-- without an asset, removes facts of assets that no longer exist, and
-- records rebuilt_at. Idempotent: running it again changes nothing.
CREATE OR REPLACE FUNCTION dash_rebuild_tenant_batch(p_tenant uuid, p_after uuid, p_limit integer)
RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
    v_none constant uuid := '00000000-0000-0000-0000-000000000000';
    v_last uuid;
    v_id   uuid;
BEGIN
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'dash_rebuild_tenant_batch: tenant is required';
    END IF;
    FOR v_id IN
        SELECT a.id FROM assets a
        WHERE a.tenant_id = p_tenant AND a.id > COALESCE(p_after, v_none)
        ORDER BY a.id
        LIMIT GREATEST(COALESCE(p_limit, 500), 1)
    LOOP
        PERFORM dash_recompute_asset(p_tenant, v_id);
        v_last := v_id;
    END LOOP;
    IF v_last IS NOT NULL THEN
        RETURN v_last;
    END IF;

    PERFORM dash_recompute_asset(p_tenant, v_none);
    DELETE FROM dash_asset_state s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    DELETE FROM dash_asset_rank s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    DELETE FROM dash_asset_day s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    INSERT INTO dash_fact_status (tenant_id, rebuilt_at) VALUES (p_tenant, now())
    ON CONFLICT (tenant_id) DO UPDATE SET rebuilt_at = EXCLUDED.rebuilt_at;
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION dash_rebuild_tenant_batch(uuid, uuid, integer) IS
    'Dashboard facts: one batch of a tenant''s full rebuild (next p_limit assets after p_after); returns the last asset id, or NULL after the final step (no-asset findings, orphan facts, dash_fact_status.rebuilt_at).';

-- Marks the assets with an open, published finding whose age band changed
-- between p_since and p_until (first detection + 31, 61 or 91 days fell in
-- that interval), and records p_until. Run daily per tenant.
CREATE OR REPLACE FUNCTION dash_mark_aged_assets(p_tenant uuid, p_since timestamptz, p_until timestamptz)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_n integer := 0;
    v_since timestamptz := COALESCE(p_since, p_until - interval '1 day');
BEGIN
    WITH crossed AS (
        SELECT DISTINCT COALESCE(f.asset_id, '00000000-0000-0000-0000-000000000000'::uuid) AS asset_id
        FROM findings f
        CROSS JOIN (VALUES (interval '31 days'), (interval '61 days'), (interval '91 days')) b(age)
        WHERE f.tenant_id = p_tenant
          AND COALESCE(f.first_detected_at, f.created_at) > v_since - b.age
          AND COALESCE(f.first_detected_at, f.created_at) <= p_until - b.age
          AND is_open_finding_status(f.status) AND NOT f.branch_only
    ), ins AS (
        INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
        SELECT p_tenant, c.asset_id, 16 FROM crossed c
        WHERE NOT EXISTS (SELECT 1 FROM dash_dirty_assets d
                          WHERE d.tenant_id = p_tenant AND d.asset_id = c.asset_id AND d.reasons & 16 = 16
                          LIMIT 1 FOR KEY SHARE SKIP LOCKED)
        ORDER BY c.asset_id
        RETURNING 1
    )
    SELECT count(*) INTO v_n FROM ins;
    INSERT INTO dash_fact_status (tenant_id, aged_marked_at) VALUES (p_tenant, p_until)
    ON CONFLICT (tenant_id) DO UPDATE SET aged_marked_at = EXCLUDED.aged_marked_at;
    RETURN v_n;
END;
$$;
COMMENT ON FUNCTION dash_mark_aged_assets(uuid, timestamptz, timestamptz) IS
    'Dashboard facts: marks assets whose open findings crossed an age band (31/61/91 days) between p_since and p_until (reason 16); records p_until in dash_fact_status.aged_marked_at.';

-- ---------------------------------------------------------------------------
-- Row-level security policies in shadow mode, like the other tenant tables
-- (row security stays off; queries filter on tenant_id).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['dash_asset_state', 'dash_asset_day', 'dash_asset_rank',
                             'dash_dirty_assets', 'dash_fact_status'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
