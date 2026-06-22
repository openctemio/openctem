-- Revert chk_asset_rel_type to the original 000039 type set.
-- NOTE: this will fail if any rows use the newly-added types
-- (cname_of, peer_of, replicates_to, has_access_to); remove or remap those
-- rows before rolling back.
ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS chk_asset_rel_type;

ALTER TABLE asset_relationships
    ADD CONSTRAINT chk_asset_rel_type CHECK (relationship_type IN (
        'runs_on', 'deployed_to', 'contains', 'exposes', 'member_of', 'resolves_to',
        'depends_on', 'sends_data_to', 'stores_data_in', 'authenticates_to', 'granted_to', 'load_balances',
        'protected_by', 'monitors', 'manages', 'owned_by'
    ));
