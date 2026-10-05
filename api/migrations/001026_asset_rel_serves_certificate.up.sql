-- research/22 E5: an HTTP probe keeps the leaf certificate it saw, and ingest
-- links the service to it with serves_certificate (configs/relationship-types.yaml).
-- The chk_asset_rel_type CHECK lists every allowed type, so the new type
-- needs it widened. The new set is a strict superset of 000168's: no existing
-- row can violate it. NOT VALID + VALIDATE keeps the exclusive lock short.
ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS chk_asset_rel_type;

ALTER TABLE asset_relationships
    ADD CONSTRAINT chk_asset_rel_type CHECK (relationship_type IN (
        -- Attack Surface Mapping
        'runs_on', 'deployed_to', 'contains', 'exposes', 'resolves_to', 'cname_of',
        'serves_certificate',
        -- Attack Path Analysis
        'depends_on', 'peer_of', 'replicates_to', 'sends_data_to', 'stores_data_in',
        'authenticates_to', 'granted_to', 'has_access_to', 'load_balances',
        -- Control & Ownership
        'protected_by', 'monitors', 'manages',
        -- Legacy values retained for backward compatibility with existing rows
        'member_of', 'owned_by'
    )) NOT VALID;

ALTER TABLE asset_relationships VALIDATE CONSTRAINT chk_asset_rel_type;
