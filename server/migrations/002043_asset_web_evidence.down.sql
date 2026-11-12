DROP TRIGGER IF EXISTS trg_asset_web_evidence_orphan ON asset_web_evidence;
DROP FUNCTION IF EXISTS asset_web_evidence_queue_orphan();
DROP TABLE IF EXISTS asset_web_evidence_orphans;
DROP TABLE IF EXISTS asset_web_evidence;
