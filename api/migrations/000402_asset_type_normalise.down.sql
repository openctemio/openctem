-- Reverts 000402 from its ledger. An asset whose type or sub-type changed
-- again after the normalisation keeps its current value (it was edited
-- since); a property the migration set is removed only while it still has
-- the value the migration gave it; the provider is restored only while it
-- is still the one the migration set. The reclassified state-history rows
-- stay: asset_state_history is append-only.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_core_type;

-- The legacy codes, back for the assets FK.
INSERT INTO asset_types
SELECT (jsonb_populate_record(NULL::asset_types, r.row_data)).*
FROM asset_types_legacy_removed r
ON CONFLICT (code) DO NOTHING;

DELETE FROM asset_dedup_review
WHERE reason = 'type_consolidation'
  AND status = 'pending'
  AND evidence->>'migration' = '402';

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
UPDATE assets a
   SET asset_type = l.old_type,
       sub_type = l.old_sub_type,
       provider = CASE WHEN a.provider IS NOT DISTINCT FROM l.new_provider THEN l.old_provider ELSE a.provider END,
       properties = a.properties - ARRAY(
           SELECT e.key FROM jsonb_each(l.added) e WHERE a.properties -> e.key = e.value
       )
  FROM asset_type_reclassifications l
 WHERE l.migration = 402
   AND a.id = l.asset_id
   AND a.tenant_id = l.tenant_id
   AND a.asset_type = l.new_type
   AND a.sub_type IS NOT DISTINCT FROM l.new_sub_type;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

DROP FUNCTION IF EXISTS asset_type_normalise_batch(UUID, INT);
DROP TABLE IF EXISTS asset_type_reclassifications;
DROP TABLE IF EXISTS asset_types_legacy_removed;
DROP TABLE IF EXISTS asset_type_legacy_codes;
