### Fixed: automations can react to failed and partial scan runs

- The `scan_completed` automation trigger now also fires for scan runs that end
  `partial` or `failed`, for automations that ask for them with
  `trigger_config.status_filter` (`completed`, `partial`, `failed`). Without a
  filter it still fires on completed runs only. An unknown outcome in the filter
  is refused on save (400 `INVALID_TRIGGER_CONFIG`).
- The run-a-scan, run-a-scan-workflow and request-AI-triage actions now fail when
  their backing service is not available, instead of reporting a successful step
  that started nothing.
