-- Platform two-factor floor (setting auth.mfa): an instance that already has
-- users keeps "none" until its operator raises it, so an upgrade never locks
-- anyone out; the row also records when the floor came into being
-- (effective_from), the start of the grace period of a managed service, whose
-- default is "admins". A fresh install has no users here, gets no row, and
-- falls to the code default (admins).

ALTER TABLE platform_settings DROP CONSTRAINT chk_platform_settings_source;
ALTER TABLE platform_settings ADD CONSTRAINT chk_platform_settings_source
    CHECK (source IN ('environment', 'console', 'migration'));

INSERT INTO platform_settings (key, value, version, source, updated_at)
SELECT 'auth.mfa',
       jsonb_build_object('floor', 'none',
                          'effective_from', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
       1, 'migration', now()
WHERE EXISTS (SELECT 1 FROM users)
ON CONFLICT (key) DO NOTHING;
