### Fixed: scan runs work for tenants without the scan workflows module

- `/api/v1/pipeline-runs` (the Scans Runs tab, a scan's run history, task
  logs, run stages and run cancel) was gated on the `scan_pipelines` module.
  The `minimal`, `asset_inventory` and `compliance` presets switch that
  module off, so those tenants got 403 `MODULE_NOT_ENABLED` on every scan
  run. The run routes now follow the core `scans` module; the permissions
  are unchanged. The scan workflow templates (`/api/v1/pipelines`) keep the
  `scan_pipelines` gate.
