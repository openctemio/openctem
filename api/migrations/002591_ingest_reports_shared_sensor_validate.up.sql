-- Validates fk_ingest_reports_sensor_id (added NOT VALID by
-- ingest_reports_shared_sensor) as its own step: SHARE UPDATE EXCLUSIVE,
-- writes keep flowing.
ALTER TABLE ingest_reports VALIDATE CONSTRAINT fk_ingest_reports_sensor_id;
