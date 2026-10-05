-- Reverts 000685. Assets the migration moved go back to
-- (application, web_application) while they still hold (application,
-- website); the reclassified history rows stay (append-only).

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
UPDATE assets a
   SET sub_type = l.old_sub_type,
       properties = a.properties - ARRAY(
           SELECT e.key FROM jsonb_each(l.added) e WHERE a.properties -> e.key = e.value
       )
  FROM asset_type_reclassifications l
 WHERE l.migration = 685
   AND a.id = l.asset_id
   AND a.tenant_id = l.tenant_id
   AND a.asset_type = l.new_type
   AND a.sub_type IS NOT DISTINCT FROM l.new_sub_type;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
DELETE FROM asset_type_reclassifications WHERE migration = 685;

-- Threat-model rows back under their old key.
DELETE FROM technique_applicability t
USING technique_applicability_subtype_moves m
WHERE m.migration = 685 AND m.inserted
  AND t.technique_id = m.technique_id AND t.asset_type = m.asset_type
  AND t.sub_type = m.new_sub_type AND t.dataset_version = m.dataset_version;
INSERT INTO technique_applicability
    (technique_id, asset_type, sub_type, edge_type, min_network, min_credential,
     requires_persistence, dataset_version)
SELECT technique_id, asset_type, old_sub_type, edge_type, min_network, min_credential,
       requires_persistence, dataset_version
FROM technique_applicability_subtype_moves
WHERE migration = 685
ON CONFLICT DO NOTHING;
DROP TABLE IF EXISTS technique_applicability_subtype_moves;

-- The registry as 000684 left it: web_application is a stored sub-type and
-- an alias type of its own again.
UPDATE asset_types SET sub_types = ARRAY['website', 'web_application', 'api', 'mobile_app']::text[]
WHERE code = 'application';
UPDATE asset_types SET class = 'application', lens = 'applications', alias_of = 'application',
       alias_sub_type = 'web_application', sub_types = '{}', is_storable = false
WHERE code = 'web_application';
DELETE FROM asset_type_input_map WHERE from_type = 'application' AND from_sub_type = 'web_application';
UPDATE asset_type_input_map SET to_type = 'application', to_sub_type = 'web_application'
WHERE from_type = 'web_application' AND from_sub_type = '';

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
BEGIN
    LOOP
        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;
        EXIT WHEN cursor_id IS NULL;
    END LOOP;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
