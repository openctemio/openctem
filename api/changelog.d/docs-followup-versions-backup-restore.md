### Fixed: restore stops the console too, sensor and SDK pins, MANAGED_SERVICE text

- `backup.sh restore` now also stops the `console` service while it replaces
  the database and volumes, so the admin console cannot write during a restore.
- `versions.yaml` pins the newest sensor (v0.23.2) and SDK (v0.34.0), so the
  install snippets and the "update available" verdict use the current releases.
- The `MANAGED_SERVICE` description names its value (`true`).
