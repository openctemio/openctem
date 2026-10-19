### Fixed: finding details no longer show sensor-local paths
- The template file, workspace and scan-mount paths a sensor reports are reduced to the rule (pack, release and path inside the pack) or the path relative to the scanned root, on ingest and when a finding is read, so stored rows need no migration.
- The finding detail shows a "Detection rule" line instead of the raw `template_path` field.
