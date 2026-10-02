-- A sensor's dispatch capacity also counts the job slots it reports (RFC-033,
-- docs/rfcs/RFC-033-sensor-manifest.md §6.1): what it can run now, sized by
-- the SDK from its CPU and memory (reported_capacity.slots_total, migration
-- 000254). Before, effective_max_jobs was min(reported_max_jobs,
-- max_concurrent_jobs) alone, and a 4-core sensor that reported the SDK's
-- upper bound (64) as its ceiling got the administrator's 5.
--
-- Kubernetes' model: reported_max_jobs is the operator's ceiling (capacity),
-- slots_total what is allocatable now; dispatch never counts on more than
-- the slots. A value that was not reported (NULL, 0) does not count; with
-- none, the administrator's limit applies alone, as before.
--
-- The same rule as Sensor.EffectiveMaxConcurrentJobs
-- (pkg/domain/sensor/reported.go); sensor_reported_caps_db_test.go keeps
-- the two in step. slots_total is clamped at ingest (1..100); the function
-- re-clamps so a hand-written row can never fail the cast.

CREATE OR REPLACE FUNCTION sensor_effective_max_jobs(admin integer, reported integer, capacity jsonb)
RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT COALESCE(
        (SELECT min(v) FROM unnest(ARRAY[
            admin,
            reported,
            CASE WHEN jsonb_typeof(capacity->'slots_total') = 'number'
                 THEN LEAST(GREATEST(floor((capacity->>'slots_total')::numeric), 0), 100)::integer
            END
        ]) AS v WHERE v > 0),
        admin)
$$;

ALTER TABLE sensors
    ALTER COLUMN effective_max_jobs
        SET EXPRESSION AS (sensor_effective_max_jobs(max_concurrent_jobs, reported_max_jobs, reported_capacity));

COMMENT ON COLUMN sensors.effective_max_jobs IS 'Capacity dispatch uses: the smallest of max_concurrent_jobs (admin), reported_max_jobs (operator ceiling) and reported_capacity.slots_total (slots now) that is set (generated).';
COMMENT ON COLUMN sensors.reported_max_jobs IS 'The sensor operator''s ceiling on concurrent jobs (SENSOR_MAX_JOBS), 1..100. NULL: none reported. What the sensor can run now is reported_capacity.slots_total.';
