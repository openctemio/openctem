ALTER TABLE sensors
    ALTER COLUMN effective_max_jobs
        SET EXPRESSION AS (
            CASE
                WHEN reported_max_jobs IS NULL OR reported_max_jobs <= 0 THEN max_concurrent_jobs
                WHEN max_concurrent_jobs IS NULL OR max_concurrent_jobs <= 0 THEN reported_max_jobs
                ELSE LEAST(reported_max_jobs, max_concurrent_jobs)
            END
        );

COMMENT ON COLUMN sensors.effective_max_jobs IS 'Capacity dispatch uses: min(reported_max_jobs, max_concurrent_jobs) (generated).';
COMMENT ON COLUMN sensors.reported_max_jobs IS 'Concurrency the sensor last reported, 1..100. NULL: never reported.';

DROP FUNCTION IF EXISTS sensor_effective_max_jobs(integer, integer, jsonb);
