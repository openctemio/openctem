-- Back to counts per asset: the host key and the likely counter go. The
-- stored counters keep their host values until each alert is planned again.
COMMENT ON COLUMN threat_alerts.confirmed_assets IS NULL;
COMMENT ON COLUMN threat_alerts.possible_assets IS NULL;
COMMENT ON COLUMN threat_alerts.internet_facing_assets IS NULL;

ALTER TABLE threat_alert_assets DROP CONSTRAINT IF EXISTS chk_threat_alert_assets_host_key;
ALTER TABLE threat_alert_assets DROP COLUMN IF EXISTS host_key;
ALTER TABLE threat_alerts DROP COLUMN IF EXISTS likely_assets;
