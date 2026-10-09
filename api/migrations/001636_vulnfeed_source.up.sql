-- The vulnerability bundle importer (RFC-066 §5.5). Off until a platform
-- admin enables it (PATCH /api/v1/admin/threat-intel/sync/vulnfeed) and the
-- pinned root key id is configured (VULNFEED_ROOT_KEY_ID).
INSERT INTO threat_intel_sync_status (source_name, sync_interval_hours, is_enabled, metadata)
VALUES ('vulnfeed', 24, false, '{}'::jsonb)
ON CONFLICT DO NOTHING;
