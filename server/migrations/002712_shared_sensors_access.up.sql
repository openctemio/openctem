-- Shared sensor access per organization (docs/rfcs/RFC-100-shared-sensors.md
-- §5): the instance administrator's allow or deny for one organization.
-- NULL: the organization follows the instance default for organizations
-- without a decision (platform setting 'shared_sensors', field new_orgs).
-- Written only by the admin console service; the organization's own opt-out
-- is an organization setting (tenants.settings, section shared_sensors).
--
-- A nullable column without a default: no table rewrite.
ALTER TABLE tenants ADD COLUMN shared_sensors_access varchar(8);
ALTER TABLE tenants ADD CONSTRAINT chk_tenants_shared_sensors_access
    CHECK (shared_sensors_access IS NULL OR shared_sensors_access IN ('allow', 'deny')) NOT VALID;

COMMENT ON COLUMN tenants.shared_sensors_access IS
    'Instance administrator''s shared sensor decision for the organization: allow, deny, or NULL (the instance default applies).';
