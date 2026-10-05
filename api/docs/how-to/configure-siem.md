# How to configure SIEM (outbound & inbound)

> **Retired 2026-10-05.** This route was part of sensor protocol v1
> (`/api/v1/agent/telemetry-events`), which was removed
> ([RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md)).
> Protocol v2 has no telemetry route yet, so SIEM inbound is unavailable
> until one ships. Stored events and the IOC catalogue are kept.

OpenCTEM integrates with a SIEM in **two independent directions**. You can set up
either or both:

- **Outbound** — forward OpenCTEM notifications to **Splunk HTTP Event Collector
  (HEC)** for centralized monitoring. Configured in the UI.
- **Inbound** — let the SIEM push detections *into* OpenCTEM so they correlate
  against the IOC catalogue and can **auto-reopen** findings (CTEM Detect/Respond).
  Architecture: [siem-ingest.md](../architecture/siem-ingest.md).

> Roles: outbound setup needs the **admin/owner** team role. Inbound uses an
> **agent API key** (not a user session).

## Outbound — forward to Splunk HEC

**Settings → Integrations → SIEM → Add Splunk HEC:**

- **Name:** e.g. "Production Splunk".
- **HEC endpoint URL:** e.g. `https://splunk.example.com:8088` (the base is fine —
  it's normalized to `…/services/collector/event`). The URL is SSRF-validated.
- **HEC token:** the Splunk HEC token (stored encrypted).
- **Index** (optional): e.g. `main`.
- **Sourcetype** (optional): e.g. `openctem:notification`.

Use the **Send** (test) action on the created integration to push a sample event
and confirm Splunk receives it.

> Outbound Splunk is delivered as a **notification provider** (same dispatch path
> as Slack/Teams/email), categorized as a notification — so it forwards the
> platform's notification stream, not a separate raw event feed.

## Inbound — SIEM detections → CTEM Detect/Respond

The SIEM is treated as a **collector**: it POSTs detections to the telemetry
endpoint using an agent key, and the correlator matches indicators against the
tenant's active IOCs (and reopens findings on a hit).

1. **Register a forwarder agent.** Create a platform agent / API key with a
   recognizable name, e.g. `splunk-forwarder` (Settings → Scanning → Agents → Add
   Agent, or a bootstrap token). Copy its key.
2. **Point the SIEM's alert action / webhook** at:
   ```
   POST /api/v1/telemetry-events
   Header: X-API-Key: <agent key>
   ```
   The tenant is derived from the agent key — never sent in the body.
3. **Send the payload** (batch, up to 100 events):
   ```json
   {
     "events": [{
       "event_type": "siem_detection",
       "severity": "high",
       "observed_at": "2026-08-30T12:00:00Z",
       "properties": {
         "remote_ip": "203.0.113.10",
         "remote_domain": "malicious.example.com",
         "file_hash": "e3b0c442...",
         "rule": "Splunk: Known-bad C2 beacon"
       }
     }]
   }
   ```
   `event_type` accepts `siem_detection`, `edr_alert`, `ioc_match`.

### Map your detection fields to the correlated keys

Correlation only fires on **specific property keys** — map the SIEM's fields onto
these or nothing matches:

| Indicator | property key(s) |
|-----------|-----------------|
| IP | `remote_ip`, `source_ip` |
| Domain | `remote_domain`, `query_name` |
| URL | `remote_url`, `url` |
| File hash | `file_hash`, `image_hash` |

Other fields (`rule`, `raw_ref`, …) are stored for context but not correlated. On
a match the correlator records an `ioc_matches` row and, if the indicator carries a
`source_finding_id`, **reopens** that finding with an audit trail ("ioc
auto-reopen: runtime match on …"). Matches are visible under **Detections**.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Splunk **Send** test fails | Wrong HEC URL/token, HEC disabled in Splunk, or the endpoint is blocked by the SSRF guard (must be reachable & not a private/blocked target per policy). |
| Nothing arrives in Splunk on real events | Outbound forwards *notifications* — confirm notifications are actually being generated. |
| Inbound events accepted but nothing correlates | Indicator fields aren't on the mapped keys above, or the value isn't in the tenant's active IOC catalogue. |
| `401` on `/telemetry-events` | Missing/invalid `X-API-Key` (agent key), or the agent isn't registered for that tenant. |
| Events land but not on a host dashboard | Events without `endpoint_asset_id` still correlate but aren't asset-scoped — expected for a multi-host forwarder. |
