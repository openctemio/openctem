-- Back to the composite FK: reports of shared sensors cannot be held by it
-- and are removed first.
DROP TRIGGER IF EXISTS trigger_ingest_reports_sensor_binding ON ingest_reports;
DROP FUNCTION IF EXISTS ingest_report_sensor_binding();
DELETE FROM ingest_reports r USING sensors s WHERE s.id = r.sensor_id AND s.scope = 'instance';
ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS fk_ingest_reports_sensor_id;
ALTER TABLE ingest_reports ADD CONSTRAINT fk_ingest_reports_sensor
    FOREIGN KEY (tenant_id, sensor_id) REFERENCES sensors (tenant_id, id) ON DELETE CASCADE;
