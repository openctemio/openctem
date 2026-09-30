-- Reverse migration 000214: remove the split-out scoping modules.
-- tenant_modules rows referencing these ids are removed first so the
-- delete does not trip the FK (tenant_modules.module_id -> modules.id).

BEGIN;

DELETE FROM tenant_modules WHERE module_id IN ('business_units', 'crown_jewels', 'threat_model');

DELETE FROM modules WHERE id IN ('business_units', 'crown_jewels', 'threat_model');

COMMIT;
