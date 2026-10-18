-- Dashboard facts maintainer (api/docs/architecture/dashboards.md, "Facts
-- maintainer"). The fact tables and change marking come from migration
-- dashboard_fact_tables; this adds what the two controllers call:
--
--   dash_process_dirty            claims a tenant's dirty rows, recomputes the
--                                 marked assets and deletes exactly the claimed
--                                 rows, in the caller's one transaction
--   dash_reconcile_asset          recomputes one asset and reports drift
--   dash_fact_run_step            one resumable step of a tenant's full run
--                                 (first build, requested rebuild, nightly
--                                 reconciliation)
--   dash_asset_day_maintain       creates the coming months' F2 partitions and
--                                 drops the ones past the history window
--
-- Live impact: three nullable columns and two counters on dash_fact_status
-- (a tiny table, no rewrite), functions only otherwise.

ALTER TABLE dash_fact_status
    ADD COLUMN IF NOT EXISTS rebuild_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS run_kind             varchar(16),
    ADD COLUMN IF NOT EXISTS run_started_at       timestamptz,
    ADD COLUMN IF NOT EXISTS run_cursor           uuid,
    ADD COLUMN IF NOT EXISTS run_drift            integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS reconciled_at        timestamptz,
    ADD COLUMN IF NOT EXISTS last_drift           integer;

ALTER TABLE dash_fact_status DROP CONSTRAINT IF EXISTS chk_dash_fact_status_run_kind;
ALTER TABLE dash_fact_status ADD CONSTRAINT chk_dash_fact_status_run_kind
    CHECK (run_kind IS NULL OR run_kind IN ('initial', 'requested', 'nightly'));

COMMENT ON TABLE dash_fact_status IS
    'Dashboard facts per tenant: rebuilt_at = last completed full run (NULL = facts not built yet); reconciled_at = same, for the nightly schedule; last_drift = fact rows the last run corrected that no change mark explained; aged_marked_at = upper bound of the last dash_mark_aged_assets run; rebuild_requested_at = last "Rebuild dashboard data" request (rate limit, at most one per hour); run_* = the run in progress (kind, start, last asset done, drift so far).';

-- ---------------------------------------------------------------------------
-- The facts loop: claim, recompute, delete, in one transaction.
-- ---------------------------------------------------------------------------

-- Claims up to p_limit of the tenant's dirty rows (oldest first) with
-- FOR UPDATE SKIP LOCKED, so it never takes a row another maintainer or a
-- still-running writer holds. Reason bits of an asset's rows are ORed; the
-- asset is recomputed when they include 1 (findings changed) or 16 (age band
-- crossed). The other reasons (asset row, group membership, ownership) do not
-- change per-asset facts and are consumed without a recompute. Exactly the
-- claimed ids are deleted. Assets are recomputed in id order, the same order
-- dash_fact_run_step uses, so two transactions never wait on each other's
-- per-asset locks in a cycle.
CREATE OR REPLACE FUNCTION dash_process_dirty(p_tenant uuid, p_limit integer)
RETURNS TABLE (claimed integer, assets integer, recomputed integer, changed integer, oldest_marked_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE
    v_ids     bigint[];
    v_asset   uuid;
    v_reasons integer;
BEGIN
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'dash_process_dirty: tenant is required';
    END IF;
    claimed := 0; assets := 0; recomputed := 0; changed := 0;

    SELECT array_agg(c.id), min(c.marked_at) INTO v_ids, oldest_marked_at
    FROM (SELECT d.id, d.marked_at FROM dash_dirty_assets d
          WHERE d.tenant_id = p_tenant
          ORDER BY d.id
          LIMIT GREATEST(COALESCE(p_limit, 500), 1)
          FOR UPDATE SKIP LOCKED) c;
    claimed := COALESCE(cardinality(v_ids), 0);
    IF claimed = 0 THEN
        RETURN NEXT;
        RETURN;
    END IF;

    FOR v_asset, v_reasons IN
        SELECT d.asset_id, bit_or(d.reasons)::integer
        FROM dash_dirty_assets d
        WHERE d.tenant_id = p_tenant AND d.id = ANY (v_ids)
        GROUP BY d.asset_id
        ORDER BY d.asset_id
    LOOP
        assets := assets + 1;
        IF v_reasons & 17 <> 0 THEN
            changed := changed + dash_recompute_asset(p_tenant, v_asset);
            recomputed := recomputed + 1;
        END IF;
    END LOOP;

    DELETE FROM dash_dirty_assets d WHERE d.tenant_id = p_tenant AND d.id = ANY (v_ids);
    RETURN NEXT;
END;
$$;
COMMENT ON FUNCTION dash_process_dirty(uuid, integer) IS
    'Dashboard facts: claims up to p_limit dirty rows of the tenant (FOR UPDATE SKIP LOCKED), recomputes assets whose ORed reasons include 1 or 16, deletes exactly the claimed rows; one transaction.';

-- ---------------------------------------------------------------------------
-- Full runs with drift detection.
-- ---------------------------------------------------------------------------

-- Recomputes one asset and returns the fact rows it corrected that no change
-- explains: 0 when the asset had a pending mark (reason 1 or 16) before or
-- after the recompute (the facts loop simply had not reached it), and 0 when
-- an open finding of the asset crossed an age band since the tenant's last
-- age-band marking or full run, whichever is later (time alone moved it). Anything else is a fact that a
-- write path failed to mark, or a recompute bug: drift. Each check is its own
-- statement, so the "after" check sees marks committed during the recompute.
CREATE OR REPLACE FUNCTION dash_reconcile_asset(p_tenant uuid, p_asset uuid) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_before boolean;
    v_n      integer;
    v_aged   timestamptz;
BEGIN
    v_before := EXISTS (SELECT 1 FROM dash_dirty_assets d
                        WHERE d.tenant_id = p_tenant AND d.asset_id = p_asset AND d.reasons & 17 <> 0);
    v_n := dash_recompute_asset(p_tenant, p_asset);
    IF v_n = 0 OR v_before THEN
        RETURN 0;
    END IF;
    IF EXISTS (SELECT 1 FROM dash_dirty_assets d
               WHERE d.tenant_id = p_tenant AND d.asset_id = p_asset AND d.reasons & 17 <> 0) THEN
        RETURN 0;
    END IF;
    -- Facts were right after the last full run and the last marking; only a
    -- crossing after the later of the two is explained by time alone.
    SELECT GREATEST(s.aged_marked_at, s.rebuilt_at) INTO v_aged FROM dash_fact_status s WHERE s.tenant_id = p_tenant;
    IF EXISTS (
        SELECT 1 FROM findings f
        CROSS JOIN (VALUES (interval '31 days'), (interval '61 days'), (interval '91 days')) b(age)
        WHERE f.tenant_id = p_tenant
          AND ((p_asset = '00000000-0000-0000-0000-000000000000'::uuid AND f.asset_id IS NULL) OR f.asset_id = p_asset)
          AND is_open_finding_status(f.status) AND NOT f.branch_only
          AND COALESCE(f.first_detected_at, f.created_at) + b.age > COALESCE(v_aged, '-infinity'::timestamptz)
          AND COALESCE(f.first_detected_at, f.created_at) + b.age <= now()) THEN
        RETURN 0;
    END IF;
    RETURN v_n;
END;
$$;
COMMENT ON FUNCTION dash_reconcile_asset(uuid, uuid) IS
    'Dashboard facts: recomputes one asset and returns the fact rows corrected without a pending change mark or an unmarked age-band crossing (drift).';

-- One step of the tenant's full run (the run kind and cursor live in
-- dash_fact_status; the caller starts a run by setting run_kind). Recomputes
-- the next p_limit assets after the cursor, adding their drift to run_drift.
-- The final step also recomputes the findings without an asset, deletes facts
-- of assets that no longer exist (counted as drift), and records rebuilt_at,
-- reconciled_at and last_drift. Runs of one tenant are serialised by a
-- transaction advisory lock (not a row lock, so a rebuild request is never
-- kept waiting). Returns done, the run kind, and this step's drift.
CREATE OR REPLACE FUNCTION dash_fact_run_step(p_tenant uuid, p_limit integer)
RETURNS TABLE (done boolean, run_kind text, step_drift integer)
LANGUAGE plpgsql AS $$
DECLARE
    v_none   constant uuid := '00000000-0000-0000-0000-000000000000';
    v_after  uuid;
    v_kind   text;
    v_last   uuid;
    v_id     uuid;
    v_drift  integer := 0;
    v_rows   integer;
BEGIN
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'dash_fact_run_step: tenant is required';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('dash_fact_run:' || p_tenant::text, 0));
    SELECT s.run_cursor, s.run_kind INTO v_after, v_kind FROM dash_fact_status s WHERE s.tenant_id = p_tenant;
    IF v_kind IS NULL THEN
        RAISE EXCEPTION 'dash_fact_run_step: no run in progress for tenant %', p_tenant;
    END IF;

    FOR v_id IN
        SELECT a.id FROM assets a
        WHERE a.tenant_id = p_tenant AND a.id > COALESCE(v_after, v_none)
        ORDER BY a.id
        LIMIT GREATEST(COALESCE(p_limit, 200), 1)
    LOOP
        v_drift := v_drift + dash_reconcile_asset(p_tenant, v_id);
        v_last := v_id;
    END LOOP;
    IF v_last IS NOT NULL THEN
        UPDATE dash_fact_status s SET run_cursor = v_last, run_drift = s.run_drift + v_drift
        WHERE s.tenant_id = p_tenant;
        done := false; run_kind := v_kind; step_drift := v_drift;
        RETURN NEXT;
        RETURN;
    END IF;

    v_drift := v_drift + dash_reconcile_asset(p_tenant, v_none);
    DELETE FROM dash_asset_state s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_drift := v_drift + v_rows;
    DELETE FROM dash_asset_rank s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_drift := v_drift + v_rows;
    DELETE FROM dash_asset_day s WHERE s.tenant_id = p_tenant AND s.asset_id <> v_none
        AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = p_tenant AND a.id = s.asset_id);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_drift := v_drift + v_rows;

    UPDATE dash_fact_status s
    SET rebuilt_at = now(), reconciled_at = now(), last_drift = s.run_drift + v_drift,
        run_kind = NULL, run_cursor = NULL, run_drift = 0
    WHERE s.tenant_id = p_tenant;
    done := true; run_kind := v_kind; step_drift := v_drift;
    RETURN NEXT;
END;
$$;
COMMENT ON FUNCTION dash_fact_run_step(uuid, integer) IS
    'Dashboard facts: one resumable step of a tenant''s full run (first build, requested rebuild, nightly reconciliation); returns done, the run kind and the drift found in this step.';

-- ---------------------------------------------------------------------------
-- F2 partitions and retention.
-- ---------------------------------------------------------------------------

-- Keeps dash_asset_day's monthly partitions: creates the next 24 months
-- (rows of such a month already sitting in the default partition are moved
-- out first by deleting them and marking their assets, since F2 is derived
-- and the facts loop writes them again), and drops the partitions that end
-- before the history window (13 months). Takes no input. SECURITY DEFINER:
-- the API role has no DDL right; this runs as the schema owner and does only
-- this. Hardening: search_path is pg_catalog then pg_temp and every
-- application object is schema-qualified, so no object or overload another
-- role creates can be picked up while running as the owner; partition names
-- come from dates alone; only children of public.dash_asset_day are dropped;
-- a short lock timeout bounds how long dashboard readers queue behind it.
-- EXECUTE is
-- revoked from PUBLIC (the app role gets it from the migrator's default
-- privileges; deploy/postgres/least-privilege-roles.sql takes it from the
-- console role). Returns the partitions created and dropped and the rows
-- moved out of the default.
CREATE OR REPLACE FUNCTION dash_asset_day_maintain()
RETURNS TABLE (created integer, dropped integer, moved integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    v_start date := public.dash_history_start();
    v_m     date := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    v_part  text;
    v_rows  integer;
    r       record;
BEGIN
    created := 0; dropped := 0; moved := 0;

    FOR i IN 0 .. 23 LOOP
        v_part := 'dash_asset_day_' || to_char(v_m, 'YYYY_MM');
        IF to_regclass('public.' || v_part) IS NULL THEN
            WITH gone AS (
                DELETE FROM public.dash_asset_day_default d
                WHERE d.day >= v_m AND d.day < (v_m + interval '1 month')::date
                RETURNING d.tenant_id, d.asset_id
            ), marks AS (
                INSERT INTO public.dash_dirty_assets (tenant_id, asset_id, reasons)
                SELECT DISTINCT g.tenant_id, g.asset_id, 1::smallint FROM gone g
                RETURNING 1
            )
            SELECT count(*) INTO v_rows FROM gone;
            moved := moved + v_rows;
            EXECUTE format('CREATE TABLE public.%I PARTITION OF public.dash_asset_day FOR VALUES FROM (%L) TO (%L)',
                           v_part, v_m, (v_m + interval '1 month')::date);
            created := created + 1;
        END IF;
        v_m := (v_m + interval '1 month')::date;
    END LOOP;

    FOR r IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'public.dash_asset_day'::regclass
          AND c.relnamespace = 'public'::regnamespace
          AND c.relname ~ '^dash_asset_day_[0-9]{4}_[0-9]{2}$'
          AND (to_date(substring(c.relname from '[0-9]{4}_[0-9]{2}$'), 'YYYY_MM') + interval '1 month')::date <= v_start
    LOOP
        -- expand-contract-ok: retention drop of dash_asset_day month partitions (table first created by 002916, in no release tag; nothing shipped reads it); partitions are dropped by the maintainer function at runtime, not by this migration
        EXECUTE format('DROP TABLE public.%I', r.relname);
        dropped := dropped + 1;
    END LOOP;
    DELETE FROM public.dash_asset_day_default d WHERE d.day < v_start;
    RETURN NEXT;
END;
$$;
REVOKE EXECUTE ON FUNCTION dash_asset_day_maintain() FROM PUBLIC;
COMMENT ON FUNCTION dash_asset_day_maintain() IS
    'Dashboard facts: creates the next 24 monthly partitions of dash_asset_day and drops those ending before dash_history_start(); SECURITY DEFINER, no input; returns created, dropped, moved (rows moved out of the default partition).';
