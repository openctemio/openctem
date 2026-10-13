-- Directory object identity (docs/architecture/asset-identity-resolution.md):
-- the Active Directory objectGUID of a computer is a strong, single-valued
-- asset identifier, so a renamed or moved computer stays the same asset.
--
-- Live impact: two CHECK constraints are replaced; existing rows already
-- satisfy the wider lists. The table is locked only while the constraints
-- are validated (one scan of asset_identifiers).

ALTER TABLE asset_identifiers DROP CONSTRAINT chk_asset_identifiers_kind;
ALTER TABLE asset_identifiers ADD CONSTRAINT chk_asset_identifiers_kind CHECK (kind IN (
    'host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'directory_object_id', 'mac', 'scm_repo_id',
    'fqdn', 'hostname', 'ip'));

ALTER TABLE asset_identifiers DROP CONSTRAINT chk_asset_identifiers_strong;
ALTER TABLE asset_identifiers ADD CONSTRAINT chk_asset_identifiers_strong CHECK (strong = (kind IN (
    'host_id', 'cloud_id', 'bios_uuid', 'serial_number', 'directory_object_id', 'mac', 'scm_repo_id')));
