-- Drop columns nothing reads or writes any more:
--   users.federated_issuer, users.federated_subject
--       moved to user_identities by 001306; empty since
--   tenants.members_without_group_see (+ chk_tenants_members_without_group_see)
--       retired by owner decision D2; 000910 pinned it to 'nothing'
--   admin_credentials.password_hash, admin_credentials.password_changed_at
--       the console signs in with the linked account plus TOTP (RFC-022 rev. 2);
--       a stale hash left here is a credential nobody can use or rotate
--   event_types.default_severity
--       never read: notification severity comes from the event itself
--   licenses.is_osi_approved, is_fsf_libre, is_deprecated, limitations
--       never read; license reports use category and risk
-- and narrow chk_sensors_type: 'agent' (pre-rename name) and 'platform' are
-- refused by the API (sensor.SensorType) and no row holds them; the column
-- default moves from 'agent' to 'worker' (every insert names the type).
--
-- Dropping a column also drops, without a word, every table constraint and
-- index that uses it. A constraint added since this list was made (for
-- example a CHECK that mentions users.federated_subject) would disappear with
-- it, so the migration stops if anything other than the one CHECK listed
-- above depends on these columns.
--
-- expand-contract-ok: contract step; no released code reads these columns
DO $$
DECLARE
    dep record;
BEGIN
    FOR dep IN
        SELECT c.conrelid::regclass::text AS tbl, c.conname AS name, a.attname AS col
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
         WHERE (c.conrelid::regclass::text, a.attname::text) IN (
                   ('users', 'federated_issuer'), ('users', 'federated_subject'),
                   ('tenants', 'members_without_group_see'),
                   ('admin_credentials', 'password_hash'), ('admin_credentials', 'password_changed_at'),
                   ('event_types', 'default_severity'),
                   ('licenses', 'is_osi_approved'), ('licenses', 'is_fsf_libre'),
                   ('licenses', 'is_deprecated'), ('licenses', 'limitations'))
           AND c.conname <> 'chk_tenants_members_without_group_see'
        UNION ALL
        SELECT i.indrelid::regclass::text, i.indexrelid::regclass::text, a.attname
          FROM pg_index i
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey::int2[])
         WHERE (i.indrelid::regclass::text, a.attname::text) IN (
                   ('users', 'federated_issuer'), ('users', 'federated_subject'),
                   ('tenants', 'members_without_group_see'),
                   ('admin_credentials', 'password_hash'), ('admin_credentials', 'password_changed_at'),
                   ('event_types', 'default_severity'),
                   ('licenses', 'is_osi_approved'), ('licenses', 'is_fsf_libre'),
                   ('licenses', 'is_deprecated'), ('licenses', 'limitations'))
    LOOP
        RAISE EXCEPTION '001483: %.% is used by % and would be dropped with it; remove that use first',
            dep.tbl, dep.col, dep.name;
    END LOOP;
END $$;

ALTER TABLE users
    DROP COLUMN IF EXISTS federated_issuer,
    DROP COLUMN IF EXISTS federated_subject;

ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see,
    DROP COLUMN IF EXISTS members_without_group_see;

ALTER TABLE admin_credentials
    DROP COLUMN IF EXISTS password_hash,
    DROP COLUMN IF EXISTS password_changed_at;

ALTER TABLE event_types DROP COLUMN IF EXISTS default_severity;

ALTER TABLE licenses
    DROP COLUMN IF EXISTS is_osi_approved,
    DROP COLUMN IF EXISTS is_fsf_libre,
    DROP COLUMN IF EXISTS is_deprecated,
    DROP COLUMN IF EXISTS limitations;

ALTER TABLE sensors ALTER COLUMN type SET DEFAULT 'worker';
ALTER TABLE sensors DROP CONSTRAINT chk_sensors_type;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_type
    CHECK (type IN ('worker', 'scanner', 'collector', 'sensor'));
