-- Reports of shared sensors (docs/rfcs/RFC-100-shared-sensors.md §8): a
-- shared sensor (scope instance) has no tenant, and its report of a shared
-- job belongs to the COMMAND's tenant. The composite FK (tenant_id,
-- sensor_id) -> sensors (tenant_id, id) cannot hold such a row, so it is
-- replaced by:
--   - a plain FK on sensor_id (the same cascade when a sensor is deleted),
--     added NOT VALID and validated by ingest_reports_shared_sensor_validate;
--   - a trigger that keeps what the composite FK guaranteed for an
--     organization sensor (the report's tenant is the sensor's tenant), and
--     binds a shared sensor's report to a shared job (is_platform_job) of the
--     report's tenant that the sensor holds. A shared sensor never stores an
--     unsolicited report.
--
-- Live impact: two short catalog changes on ingest_reports (no rewrite, no
-- scan); the trigger costs one primary-key lookup per inserted report.

ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS fk_ingest_reports_sensor;
ALTER TABLE ingest_reports ADD CONSTRAINT fk_ingest_reports_sensor_id
    FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE NOT VALID;

CREATE OR REPLACE FUNCTION ingest_report_sensor_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_scope  varchar;
    v_tenant uuid;
BEGIN
    SELECT s.scope, s.tenant_id INTO v_scope, v_tenant FROM sensors s WHERE s.id = NEW.sensor_id;
    IF NOT FOUND THEN
        RETURN NEW; -- the FK refuses an unknown sensor
    END IF;
    IF v_scope = 'instance' THEN
        IF NEW.command_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM commands c
            WHERE c.id = NEW.command_id AND c.tenant_id = NEW.tenant_id
              AND c.is_platform_job AND c.sensor_id = NEW.sensor_id) THEN
            RAISE EXCEPTION 'a shared sensor stores a report only for a shared job of that tenant it holds (sensor %)', NEW.sensor_id
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF v_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'report tenant does not match the tenant of sensor %', NEW.sensor_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION ingest_report_sensor_binding() IS
    'BEFORE INSERT OR UPDATE on ingest_reports: an organization sensor''s report is in its tenant; a shared sensor''s report names a shared job of the report''s tenant that the sensor holds.';

CREATE TRIGGER trigger_ingest_reports_sensor_binding
    BEFORE INSERT OR UPDATE OF tenant_id, sensor_id, command_id ON ingest_reports
    FOR EACH ROW EXECUTE FUNCTION ingest_report_sensor_binding();
