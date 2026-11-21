-- An emerging-threat alert counts hosts (docs/architecture/emerging-threat-alerts.md,
-- "Counting hosts"): a host that serves several ports has one service asset
-- per port and is one affected host. Each alert asset stores the key of the
-- host row it belongs to, written by the planner (threatalert.HostKey), so
-- the scoped counts of the list and the digest are a distinct count. "Likely"
-- gets its own stored counter beside confirmed and possible.
--
-- Additive: both columns have a constant default (no table rewrite). Rows
-- written before this migration have an empty key and count as a host of
-- their own until the API fills them at start (postgres.BackfillThreatAlertHosts),
-- which also recomputes the stored counters of their alerts.

ALTER TABLE threat_alerts ADD COLUMN likely_assets INTEGER NOT NULL DEFAULT 0;

ALTER TABLE threat_alert_assets ADD COLUMN host_key TEXT NOT NULL DEFAULT '';
ALTER TABLE threat_alert_assets ADD CONSTRAINT chk_threat_alert_assets_host_key
    CHECK (length(host_key) <= 300) NOT VALID;
ALTER TABLE threat_alert_assets VALIDATE CONSTRAINT chk_threat_alert_assets_host_key;

COMMENT ON COLUMN threat_alerts.confirmed_assets IS
    'Hosts with a confirmed match, whole organization (a host that serves several ports is one).';
COMMENT ON COLUMN threat_alerts.likely_assets IS
    'Hosts with a likely match (a version match below the confirmed confidence), whole organization.';
COMMENT ON COLUMN threat_alerts.possible_assets IS
    'Hosts possibly affected (product known, version unknown), whole organization.';
COMMENT ON COLUMN threat_alerts.internet_facing_assets IS
    'Affected hosts with an internet-facing service, whole organization.';
COMMENT ON COLUMN threat_alert_assets.host_key IS
    'Host row of the asset within its alert: h:<host> for an asset named by a URL, a:<asset id> otherwise; empty until backfilled.';
