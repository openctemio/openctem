### Removed: sensor protocol v1 (`/api/v1/agent/*`) and the `/api/v1/agents` redirects

- Every route under `/api/v1/agent` now answers 404: heartbeat, command poll and transitions, key renewal, suppressions, CTIS/chunk ingest, fingerprint check and baseline diff, async job status, and the routes that had no protocol v2 successor (`ingest/sarif`, `ingest/recon`, `ingest/scan`, `ingest/scanners`, `scans`, `telemetry-events`, `credentials/ingest`). Sensors use protocol v2 (`/api/v2/sensor/*`) for the whole surface.
- The deprecated management path `/api/v1/agents/*` (308 to `/api/v1/sensors`) is gone; use `/api/v1/sensors`.
- Job payloads no longer carry `agent_preference`; the `results-v2` advert header, the v1 deprecation entry in `GET /api/v2/sensor/hello` and the `ingest_v1_requests_total` metric are gone.
- SIEM inbound (runtime telemetry posted with a sensor key) has no protocol v2 route yet, so it is unavailable; stored telemetry and the IOC catalogue are kept. Administrators still import leaked credentials through `/api/v1/credentials/import`.
- No migration.
- **Upgrade note:** sensors older than v0.9.0 stop working. Upgrade every sensor to v0.9.0 or later before deploying this API (the Sensors page shows a sensor's protocol; anything still on protocol 1 must be upgraded).
