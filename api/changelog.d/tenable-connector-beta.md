### Added: the Tenable.sc connector is on, as Beta

- Tenable.sc integrations can be created again: the connector runs as its own image, `ghcr.io/openctemio/connector-tenable` (v0.1.0), paired like a sensor with the `scan-connector` grant profile. Syncs, scans launched and scheduled from OpenCTEM and licence-aware rolling coverage work; the sync and coverage controllers run. The integration page shows a Beta badge, and its text is translated (en, vi).
- Beta until a run against a real Tenable.sc confirms what only the documentation states. Known: the API states `maxScanTime` without a unit, so Tenable.sc may allow a scan to run longer than asked; the connector stops a scan itself at its maximum duration plus 30 minutes for the import.
