-- Back to the 000168 type set. serves_certificate edges are derived data
-- (ingest re-creates them from the next HTTP probe), so they are removed
-- rather than blocking the rollback.
DELETE FROM asset_relationships WHERE relationship_type = 'serves_certificate';

ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS chk_asset_rel_type;

ALTER TABLE asset_relationships
    ADD CONSTRAINT chk_asset_rel_type CHECK (relationship_type IN (
        'runs_on', 'deployed_to', 'contains', 'exposes', 'resolves_to', 'cname_of',
        'depends_on', 'peer_of', 'replicates_to', 'sends_data_to', 'stores_data_in',
        'authenticates_to', 'granted_to', 'has_access_to', 'load_balances',
        'protected_by', 'monitors', 'manages',
        'member_of', 'owned_by'
    ));
