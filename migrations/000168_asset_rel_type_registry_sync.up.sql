-- Reconcile the asset_relationships type CHECK constraint with the relationship
-- type registry (configs/relationship-types.yaml → relationship_types_generated.go).
--
-- The registry added cname_of, peer_of, replicates_to and has_access_to, but the
-- chk_asset_rel_type CHECK (added in 000039) was never updated. Those four types
-- pass domain validation (IsValid) then fail INSERT with a 23514 CHECK violation,
-- surfacing as a 500 on relationship create / suggestion approve.
--
-- The new constraint is a strict SUPERSET of the old one: it keeps the legacy
-- member_of / owned_by values (so existing rows remain valid) and adds the four
-- registry types. No existing row can violate it.
ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS chk_asset_rel_type;

ALTER TABLE asset_relationships
    ADD CONSTRAINT chk_asset_rel_type CHECK (relationship_type IN (
        -- Attack Surface Mapping
        'runs_on', 'deployed_to', 'contains', 'exposes', 'resolves_to', 'cname_of',
        -- Attack Path Analysis
        'depends_on', 'peer_of', 'replicates_to', 'sends_data_to', 'stores_data_in',
        'authenticates_to', 'granted_to', 'has_access_to', 'load_balances',
        -- Control & Ownership
        'protected_by', 'monitors', 'manages',
        -- Legacy values retained for backward compatibility with existing rows
        'member_of', 'owned_by'
    ));
