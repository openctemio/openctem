-- Write-path cost of the dashboard fact triggers (migration
-- dashboard_fact_tables). Run on a SCRATCH database migrated to the head,
-- never on a shared or live one: it seeds a tenant, toggles triggers on
-- findings with ALTER TABLE and removes everything at the end.
--
--   psql "postgres://.../openctem_bench" -v ON_ERROR_STOP=1 -f scripts/perf/dashboard_fact_triggers_bench.sql
--
-- Each scenario runs :batches statements of :batch rows, every statement in
-- its own transaction (as ingest does), with the fact triggers off, on, and
-- on with a row-level update trigger instead of the statement-level one
-- ("row", for comparison only). Rounds alternate the order of the modes.
-- Prints the median milliseconds per scenario and mode, and the overhead.

\set assets 2000
\set seed_findings 200000
\set batch 500
\set batches 40
\set rounds 7

SET client_min_messages = warning;

DO $$ BEGIN
    IF current_database() !~ '(_test|_bench)$' THEN
        RAISE EXCEPTION 'refusing to run on database %: use a scratch *_test or *_bench database', current_database();
    END IF;
END $$;

CREATE TABLE bench_results (mode text, round int, scenario text, ms numeric);

INSERT INTO tenants (id, name, slug)
VALUES ('b0000000-0000-0000-0000-000000000001', 'Dashboard trigger bench', 'dash-trigger-bench');

INSERT INTO assets (id, tenant_id, name, asset_type)
SELECT ('b1000000-0000-0000-0000-' || lpad(g::text, 12, '0'))::uuid,
       'b0000000-0000-0000-0000-000000000001', 'bench-host-' || g, 'host'
FROM generate_series(1, :assets) g;

-- Existing findings so the indexes have a realistic size.
INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, description, severity, fingerprint,
                      status, priority_class, first_detected_at)
SELECT 'b0000000-0000-0000-0000-000000000001',
       ('b1000000-0000-0000-0000-' || lpad((1 + g % :assets)::text, 12, '0'))::uuid,
       'sast', 'bench', 'seed finding ' || g, repeat('d', 800),
       (ARRAY['critical', 'high', 'medium', 'low'])[1 + g % 4], 'seed-' || g,
       (ARRAY['new', 'confirmed', 'resolved', 'false_positive'])[1 + g % 4],
       (ARRAY['P0', 'P1', 'P2', 'P3'])[1 + g % 4], now() - (g % 400) * interval '1 day'
FROM generate_series(1, :seed_findings) g;
DELETE FROM dash_dirty_assets WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001';
ANALYZE findings;
ANALYZE dash_dirty_assets;

-- The comparison variant: a row-level update trigger limited to the fact
-- input columns by a WHEN clause (fires per changed row instead of once per
-- statement).
CREATE FUNCTION bench_dash_mark_update_row() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
    PERFORM dash_mark_asset(NEW.tenant_id, NEW.asset_id, 1::smallint);
    IF OLD.asset_id IS DISTINCT FROM NEW.asset_id THEN
        PERFORM dash_mark_asset(OLD.tenant_id, OLD.asset_id, 1::smallint);
    END IF;
    RETURN NULL;
END $f$;

CREATE PROCEDURE bench_set_mode(p_mode text) LANGUAGE plpgsql AS $p$
BEGIN
    DROP TRIGGER IF EXISTS bench_trg_update_row ON findings;
    IF p_mode = 'off' THEN
        ALTER TABLE findings DISABLE TRIGGER trg_findings_dash_insert;
        ALTER TABLE findings DISABLE TRIGGER trg_findings_dash_delete;
        ALTER TABLE findings DISABLE TRIGGER trg_findings_dash_update;
    ELSE
        ALTER TABLE findings ENABLE TRIGGER trg_findings_dash_insert;
        ALTER TABLE findings ENABLE TRIGGER trg_findings_dash_delete;
        IF p_mode = 'row' THEN
            ALTER TABLE findings DISABLE TRIGGER trg_findings_dash_update;
            CREATE TRIGGER bench_trg_update_row
                AFTER UPDATE OF status, severity, priority_class, sla_status, asset_id, is_in_kev, epss_score ON findings
                FOR EACH ROW
                WHEN ((OLD.status, OLD.severity, OLD.priority_class, OLD.sla_status, OLD.asset_id, OLD.is_in_kev, OLD.epss_score)
                      IS DISTINCT FROM (NEW.status, NEW.severity, NEW.priority_class, NEW.sla_status, NEW.asset_id, NEW.is_in_kev, NEW.epss_score))
                EXECUTE FUNCTION bench_dash_mark_update_row();
        ELSE
            ALTER TABLE findings ENABLE TRIGGER trg_findings_dash_update;
        END IF;
    END IF;
END $p$;

CREATE PROCEDURE bench_round(p_mode text, p_round int, p_batch int, p_batches int, p_assets int)
LANGUAGE plpgsql AS $p$
DECLARE
    t0 timestamptz;
    tag text;
    k int;
BEGIN
    CALL bench_set_mode(p_mode);
    COMMIT;
    tag := p_mode || '-' || p_round;

    -- New findings: one scan batch spreads over a few assets.
    t0 := clock_timestamp();
    FOR b IN 1 .. p_batches LOOP
        INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, description, severity, fingerprint,
                              status, priority_class, first_detected_at)
        SELECT 'b0000000-0000-0000-0000-000000000001',
               ('b1000000-0000-0000-0000-' || lpad((1 + (b * 5 + g % 5) % p_assets)::text, 12, '0'))::uuid,
               'sast', 'bench', 'bench finding', repeat('d', 800),
               (ARRAY['critical', 'high', 'medium', 'low'])[1 + g % 4], 'run-' || tag || '-' || b || '-' || g,
               'new', 'P2', now()
        FROM generate_series(1, p_batch) g;
        COMMIT;
    END LOOP;
    INSERT INTO bench_results VALUES (p_mode, p_round, '1 insert new', extract(epoch FROM clock_timestamp() - t0) * 1000);
    COMMIT;

    -- Re-sighting: last_seen_at, occurrence count, metadata (no fact input).
    t0 := clock_timestamp();
    FOR b IN 1 .. p_batches LOOP
        UPDATE findings SET last_seen_at = now(), occurrence_count = occurrence_count + 1,
                            metadata = metadata || '{"seen": 1}'
        WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001' AND fingerprint LIKE 'run-' || tag || '-' || b || '-%';
        COMMIT;
    END LOOP;
    INSERT INTO bench_results VALUES (p_mode, p_round, '2 re-sight update', extract(epoch FROM clock_timestamp() - t0) * 1000);
    COMMIT;

    -- Upsert of existing fingerprints with unchanged severity (conflict path).
    t0 := clock_timestamp();
    FOR b IN 1 .. p_batches LOOP
        INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
        SELECT 'b0000000-0000-0000-0000-000000000001',
               ('b1000000-0000-0000-0000-' || lpad((1 + (b * 5 + g % 5) % p_assets)::text, 12, '0'))::uuid,
               'sast', 'bench', 'bench finding', (ARRAY['critical', 'high', 'medium', 'low'])[1 + g % 4],
               'run-' || tag || '-' || b || '-' || g, 'new'
        FROM generate_series(1, p_batch) g
        ON CONFLICT (tenant_id, fingerprint) DO UPDATE
            SET last_seen_at = now(), severity = EXCLUDED.severity, message = EXCLUDED.message;
        COMMIT;
    END LOOP;
    INSERT INTO bench_results VALUES (p_mode, p_round, '3 upsert existing', extract(epoch FROM clock_timestamp() - t0) * 1000);
    COMMIT;

    -- Bulk status change (a fact input).
    t0 := clock_timestamp();
    FOR b IN 1 .. p_batches LOOP
        UPDATE findings SET status = 'confirmed'
        WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001' AND fingerprint LIKE 'run-' || tag || '-' || b || '-%';
        COMMIT;
    END LOOP;
    INSERT INTO bench_results VALUES (p_mode, p_round, '4 status update', extract(epoch FROM clock_timestamp() - t0) * 1000);
    COMMIT;

    -- Delete the round's findings.
    t0 := clock_timestamp();
    FOR b IN 1 .. p_batches LOOP
        DELETE FROM findings
        WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001' AND fingerprint LIKE 'run-' || tag || '-' || b || '-%';
        COMMIT;
    END LOOP;
    INSERT INTO bench_results VALUES (p_mode, p_round, '5 delete', extract(epoch FROM clock_timestamp() - t0) * 1000);
    COMMIT;

    -- The maintainer drains the queue between rounds.
    SELECT count(*) INTO k FROM dash_dirty_assets WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001';
    INSERT INTO bench_results VALUES (p_mode, p_round, '9 queue rows', k);
    DELETE FROM dash_dirty_assets WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001';
    COMMIT;
END $p$;

CREATE INDEX bench_findings_fp_prefix ON findings (tenant_id, fingerprint text_pattern_ops);
-- findings.duplicate_of has no index, so every deleted finding scans the
-- table for the self-reference check; index it here so the delete scenario
-- measures the triggers.
CREATE INDEX bench_findings_duplicate_of ON findings (duplicate_of) WHERE duplicate_of IS NOT NULL;

DO $$ BEGIN RAISE WARNING 'seeded; running rounds'; END $$;

SELECT format('CALL bench_round(%L, %s, %s, %s, %s)', m, r, :batch, :batches, :assets)
FROM generate_series(1, :rounds) r,
     LATERAL unnest(CASE WHEN r % 2 = 0 THEN ARRAY['off', 'on', 'row'] ELSE ARRAY['row', 'on', 'off'] END)
         WITH ORDINALITY AS u(m, o)
ORDER BY r, o \gexec

WITH med AS (
    SELECT scenario, mode, percentile_cont(0.5) WITHIN GROUP (ORDER BY ms) AS ms
    FROM bench_results GROUP BY scenario, mode
)
SELECT scenario,
       round((SELECT ms FROM med m WHERE m.scenario = s.scenario AND mode = 'off')::numeric, 1) AS off_ms,
       round((SELECT ms FROM med m WHERE m.scenario = s.scenario AND mode = 'on')::numeric, 1) AS on_ms,
       round((SELECT ms FROM med m WHERE m.scenario = s.scenario AND mode = 'row')::numeric, 1) AS row_ms,
       round((100 * ((SELECT ms FROM med m WHERE m.scenario = s.scenario AND mode = 'on')
              / NULLIF((SELECT ms FROM med m WHERE m.scenario = s.scenario AND mode = 'off'), 0) - 1))::numeric, 1)
           AS on_overhead_pct
FROM (SELECT DISTINCT scenario FROM bench_results) s
ORDER BY scenario;

-- Clean up (findings first, while the duplicate_of index still exists).
CALL bench_set_mode('on');
DELETE FROM findings WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001';
DELETE FROM assets WHERE tenant_id = 'b0000000-0000-0000-0000-000000000001';
DELETE FROM tenants WHERE id = 'b0000000-0000-0000-0000-000000000001';
DROP INDEX bench_findings_fp_prefix;
DROP INDEX bench_findings_duplicate_of;
DROP PROCEDURE bench_round(text, int, int, int, int);
DROP PROCEDURE bench_set_mode(text);
DROP FUNCTION bench_dash_mark_update_row();
DROP TABLE bench_results;
