-- Validates the CHECK added NOT VALID in shared_sensors_access (a scan of
-- tenants without blocking writes).
ALTER TABLE tenants VALIDATE CONSTRAINT chk_tenants_shared_sensors_access;
