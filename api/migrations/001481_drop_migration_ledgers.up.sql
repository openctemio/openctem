-- Drop the ledger, archive and backup tables that data migrations kept so
-- that their own down migrations could put rows back. Every forward step they
-- belong to is final on every deployment, and nothing in the application
-- reads them:
--   access_control_removed_archive       permission rows removed by 000670,
--                                        001179, 001184 and 001286
--   asset_type_input_map,                the asset type normalisation
--   asset_type_legacy_codes,             (000684/000685); the Go registry maps
--   asset_types_legacy_removed,          accepted input names and
--   asset_type_reclassifications,        chk_assets_core_type refuses a
--   asset_type_normalise_batch()         non-core type
--   asset_properties_pre_001185          property values before 001185
--   easm_ct_rekey_001018                 CT findings before 001018
--   granular_permission_backfill         role grants added by 000771
--   technique_applicability_rekey_ledger,
--   technique_applicability_subtype_moves  threat-model rows moved by 000684/685
--   legacy_templates_backup_001322,
--   legacy_template_steps_backup_001322  scan templates before 001322
--
-- The rows are rollback data only. The pre-upgrade backup keeps them; the down
-- migration recreates the tables empty, so a down migration of 001322, 001286,
-- 001185, 001184 or 001179 run after this one restores nothing.
--
-- expand-contract-ok: contract step; nothing reads these objects
DROP FUNCTION IF EXISTS asset_type_normalise_batch(uuid, integer, integer);
DROP TABLE IF EXISTS access_control_removed_archive;
DROP TABLE IF EXISTS asset_type_input_map;
DROP TABLE IF EXISTS asset_type_legacy_codes;
DROP TABLE IF EXISTS asset_types_legacy_removed;
DROP TABLE IF EXISTS asset_type_reclassifications;
DROP TABLE IF EXISTS asset_properties_pre_001185;
DROP TABLE IF EXISTS easm_ct_rekey_001018;
DROP TABLE IF EXISTS granular_permission_backfill;
DROP TABLE IF EXISTS technique_applicability_rekey_ledger;
DROP TABLE IF EXISTS technique_applicability_subtype_moves;
DROP TABLE IF EXISTS legacy_templates_backup_001322;
DROP TABLE IF EXISTS legacy_template_steps_backup_001322;
