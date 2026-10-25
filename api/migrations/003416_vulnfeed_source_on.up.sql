-- The vulnerability bundles are signed under a root key id pinned in the
-- platform (VULNFEED_ROOT_KEY_ID overrides it), so the importer needs no setup:
-- turn the source on. A platform admin can still switch it off.
UPDATE threat_intel_sync_status SET is_enabled = true WHERE source_name = 'vulnfeed';
