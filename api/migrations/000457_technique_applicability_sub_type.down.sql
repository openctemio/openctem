-- Reverts 000457: restores the alias-keyed rows from the ledger and the
-- (technique_id, asset_type, dataset_version) primary key.

-- Rows the up migration inserted for a moved row.
DELETE FROM technique_applicability t
USING technique_applicability_rekey_ledger l
WHERE l.inserted
  AND t.technique_id = l.technique_id
  AND t.asset_type = l.new_asset_type
  AND t.sub_type = l.new_sub_type
  AND t.dataset_version = l.dataset_version;

-- Any other row with a sub-type cannot exist under the old key.
DELETE FROM technique_applicability WHERE sub_type <> '';

ALTER TABLE technique_applicability DROP CONSTRAINT IF EXISTS technique_applicability_pkey;
ALTER TABLE technique_applicability DROP COLUMN IF EXISTS sub_type;

INSERT INTO technique_applicability
    (technique_id, asset_type, edge_type, min_network, min_credential, requires_persistence, dataset_version)
SELECT technique_id, old_asset_type, edge_type, min_network, min_credential, requires_persistence, dataset_version
FROM technique_applicability_rekey_ledger;

ALTER TABLE technique_applicability
    ADD CONSTRAINT technique_applicability_pkey PRIMARY KEY (technique_id, asset_type, dataset_version);

DROP TABLE IF EXISTS technique_applicability_rekey_ledger;
