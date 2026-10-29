-- dashboard_flow_panel_at (up)
-- NULL = the exposure flow panel was never offered on this dashboard (every
-- existing row, so each is offered once); new rows default to now() so a
-- freshly created dashboard is never auto-offered. Two statements: adding the
-- column without a default leaves existing rows NULL and rewrites nothing.
ALTER TABLE user_dashboards ADD COLUMN IF NOT EXISTS flow_panel_at timestamptz;
ALTER TABLE user_dashboards ALTER COLUMN flow_panel_at SET DEFAULT now();
COMMENT ON COLUMN user_dashboards.flow_panel_at IS
  'When the exposure flow panel was offered on this dashboard (added once, or found already present). NULL means never offered. Never cleared, so a panel the user removed is not added again.';
