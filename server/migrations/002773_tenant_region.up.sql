-- The data region of an organization (RFC-104): set once when it is created,
-- from the deployment's DEPLOYMENT_REGION, and never changed afterwards.
-- NULL for organizations created before (one region; shown as the
-- deployment's). tenants is a small table: adding a nullable column and a
-- check that every existing NULL passes is brief.
ALTER TABLE tenants
    ADD COLUMN region text,
    ADD CONSTRAINT chk_tenants_region CHECK (region IS NULL OR region ~ '^[a-z0-9][a-z0-9-]{0,31}$');
