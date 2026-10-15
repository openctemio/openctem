-- Every timeline entry of a status change records the version of the
-- lifecycle rules it was decided under (pkg/domain/vulnerability
-- lifecycle_version.go), so an audit can tell which rules applied when a
-- finding moved. Today there is one platform lifecycle, "platform:1"; a
-- tenant lifecycle scheme will record its own version here.
--
-- A BEFORE INSERT trigger fills it on every entry whose changes name a new
-- status, whatever writer inserted it (a person's move, a platform writer, the
-- transition timeline trigger), and copies it into changes for display.
-- Nullable column: a catalog change on a populated table; old entries stay
-- NULL (decided before versions were recorded).

ALTER TABLE finding_activities ADD COLUMN lifecycle_version varchar(64);

COMMENT ON COLUMN finding_activities.lifecycle_version IS
    'Version of the lifecycle rules a status change was decided under (lifecycle_version.go); NULL for other entries and before 2026-10';

CREATE OR REPLACE FUNCTION finding_lifecycle_version()
RETURNS text
LANGUAGE sql
IMMUTABLE PARALLEL SAFE
AS $$
    SELECT 'platform:1'::text
$$;

COMMENT ON FUNCTION finding_lifecycle_version() IS
    'The platform lifecycle version (vulnerability.PlatformLifecycleVersion; a test pins them)';

CREATE OR REPLACE FUNCTION finding_activity_lifecycle_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.lifecycle_version IS NULL AND NEW.changes ? 'new_status' THEN
        NEW.lifecycle_version := COALESCE(NULLIF(NEW.changes->>'lifecycle_version', ''), finding_lifecycle_version());
    END IF;
    IF NEW.lifecycle_version IS NOT NULL THEN
        NEW.changes := COALESCE(NEW.changes, '{}'::jsonb) || jsonb_build_object('lifecycle_version', NEW.lifecycle_version);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_finding_activities_lifecycle_version
    BEFORE INSERT ON finding_activities
    FOR EACH ROW
    EXECUTE FUNCTION finding_activity_lifecycle_version();
