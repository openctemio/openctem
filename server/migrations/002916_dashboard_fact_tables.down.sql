-- Removes the dashboard fact layer: triggers first (so no write path calls a
-- dropped function), then functions and tables. The facts are derived data;
-- nothing else is lost.
DROP TRIGGER IF EXISTS trg_findings_dash_insert ON findings;
DROP TRIGGER IF EXISTS trg_findings_dash_delete ON findings;
DROP TRIGGER IF EXISTS trg_findings_dash_update ON findings;
DROP TRIGGER IF EXISTS trg_assets_dash_insert ON assets;
DROP TRIGGER IF EXISTS trg_assets_dash_delete ON assets;
DROP TRIGGER IF EXISTS trg_assets_dash_update ON assets;
DROP TRIGGER IF EXISTS trg_asset_group_members_dash_insert ON asset_group_members;
DROP TRIGGER IF EXISTS trg_asset_group_members_dash_delete ON asset_group_members;
DROP TRIGGER IF EXISTS trg_asset_group_members_dash_update_new ON asset_group_members;
DROP TRIGGER IF EXISTS trg_asset_group_members_dash_update_old ON asset_group_members;
DROP TRIGGER IF EXISTS trg_asset_owners_dash_insert ON asset_owners;
DROP TRIGGER IF EXISTS trg_asset_owners_dash_delete ON asset_owners;
DROP TRIGGER IF EXISTS trg_asset_owners_dash_update_new ON asset_owners;
DROP TRIGGER IF EXISTS trg_asset_owners_dash_update_old ON asset_owners;

DROP FUNCTION IF EXISTS dash_mark_aged_assets(uuid, timestamptz, timestamptz);
DROP FUNCTION IF EXISTS dash_rebuild_tenant_batch(uuid, uuid, integer);
DROP FUNCTION IF EXISTS dash_recompute_asset(uuid, uuid);
DROP FUNCTION IF EXISTS dash_mark_from_member_rows();
DROP FUNCTION IF EXISTS dash_mark_asset_update();
DROP FUNCTION IF EXISTS dash_mark_from_asset_rows();
DROP FUNCTION IF EXISTS dash_mark_from_finding_update();
DROP FUNCTION IF EXISTS dash_mark_asset(uuid, uuid, smallint);
DROP FUNCTION IF EXISTS dash_mark_from_finding_rows();

DROP TABLE IF EXISTS dash_fact_status;
DROP TABLE IF EXISTS dash_dirty_assets;
DROP TABLE IF EXISTS dash_asset_rank;
DROP TABLE IF EXISTS dash_asset_day;
DROP TABLE IF EXISTS dash_asset_state;

DROP FUNCTION IF EXISTS dash_history_start();
DROP FUNCTION IF EXISTS dash_asset_day_ensure_partitions(date, integer);
DROP FUNCTION IF EXISTS dash_fix_hours_bucket(double precision);
DROP FUNCTION IF EXISTS dash_age_band(text, timestamptz);
DROP FUNCTION IF EXISTS dash_sla_state(text);
DROP FUNCTION IF EXISTS dash_finding_lens(text);
