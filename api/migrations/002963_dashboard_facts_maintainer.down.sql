-- Removes the facts maintainer's functions and run columns. The fact tables
-- and their partitions (including any the maintainer created) stay with
-- migration dashboard_fact_tables.
DROP FUNCTION IF EXISTS dash_asset_day_maintain();
DROP FUNCTION IF EXISTS dash_fact_run_step(uuid, integer);
DROP FUNCTION IF EXISTS dash_reconcile_asset(uuid, uuid);
DROP FUNCTION IF EXISTS dash_process_dirty(uuid, integer);

ALTER TABLE dash_fact_status DROP CONSTRAINT IF EXISTS chk_dash_fact_status_run_kind;
ALTER TABLE dash_fact_status
    DROP COLUMN IF EXISTS rebuild_requested_at,
    DROP COLUMN IF EXISTS run_kind,
    DROP COLUMN IF EXISTS run_started_at,
    DROP COLUMN IF EXISTS run_cursor,
    DROP COLUMN IF EXISTS run_drift,
    DROP COLUMN IF EXISTS reconciled_at,
    DROP COLUMN IF EXISTS last_drift;

COMMENT ON TABLE dash_fact_status IS
    'Dashboard facts per tenant: rebuilt_at = last completed full rebuild (NULL = facts not built yet); aged_marked_at = upper bound of the last dash_mark_aged_assets run.';
