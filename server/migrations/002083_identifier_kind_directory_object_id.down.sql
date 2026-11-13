-- Directory object identifiers are removed: the old constraints do not allow
-- the kind. The assets keep their objectGUID in properties.ad_object_guid.

DELETE FROM asset_identifiers WHERE kind = 'directory_object_id';

ALTER TABLE asset_identifiers DROP CONSTRAINT chk_asset_identifiers_kind;
ALTER TABLE asset_identifiers ADD CONSTRAINT chk_asset_identifiers_kind CHECK (kind IN (
    'host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'mac', 'scm_repo_id', 'fqdn', 'hostname', 'ip'));

ALTER TABLE asset_identifiers DROP CONSTRAINT chk_asset_identifiers_strong;
ALTER TABLE asset_identifiers ADD CONSTRAINT chk_asset_identifiers_strong CHECK (strong = (kind IN (
    'host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'mac', 'scm_repo_id')));
