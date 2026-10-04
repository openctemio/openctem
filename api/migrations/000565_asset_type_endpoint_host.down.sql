-- Reverts 000565: endpoint is a core type again. Assets the migration moved
-- go back to endpoint while they still hold (host, workstation); the
-- reclassified history rows stay (append-only).

ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_core_type;

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
UPDATE assets a
   SET asset_type = l.old_type,
       sub_type = l.old_sub_type,
       properties = a.properties - ARRAY(
           SELECT e.key FROM jsonb_each(l.added) e WHERE a.properties -> e.key = e.value
       )
  FROM asset_type_reclassifications l
 WHERE l.migration = 565
   AND a.id = l.asset_id
   AND a.tenant_id = l.tenant_id
   AND a.asset_type = l.new_type
   AND a.sub_type IS NOT DISTINCT FROM l.new_sub_type;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
DELETE FROM asset_type_reclassifications WHERE migration = 565;

UPDATE asset_types SET sub_types = array_remove(sub_types, $q$workstation$q$) WHERE code = $q$host$q$;
UPDATE asset_types SET alias_of = NULL, alias_sub_type = NULL, is_storable = true, class = $q$host$q$, lens = $q$cloud_infra$q$
WHERE code = $q$endpoint$q$;
DELETE FROM asset_type_input_map WHERE from_type = $q$endpoint$q$ AND from_sub_type = $q$$q$;

ALTER TABLE assets ADD CONSTRAINT chk_assets_core_type CHECK (asset_type IN (
    $q$domain$q$, $q$subdomain$q$, $q$ip_address$q$, $q$certificate$q$, $q$service$q$, $q$application$q$,
    $q$host$q$, $q$endpoint$q$, $q$cloud_account$q$, $q$container$q$, $q$kubernetes$q$, $q$repository$q$,
    $q$identity$q$, $q$database$q$, $q$storage$q$, $q$network$q$, $q$unclassified$q$)) NOT VALID;
ALTER TABLE assets VALIDATE CONSTRAINT chk_assets_core_type;

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $do$
DECLARE
    cursor_id uuid := NULL;
BEGIN
    LOOP
        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;
        EXIT WHEN cursor_id IS NULL;
    END LOOP;
END $do$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
