# How to configure SIEM forwarding

> **Inbound is unavailable.** It used sensor protocol v1, which was removed
> ([RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md)).
> Stored events and the IOC catalogue are kept.

OpenCTEM integrates with a SIEM in two directions:

- **Outbound** — forward OpenCTEM notifications to **Splunk HTTP Event Collector
  (HEC)** for centralized monitoring. Configured in the UI.
- **Inbound** — let the SIEM push detections *into* OpenCTEM (currently
  unavailable, see below).

> Roles: outbound setup needs the **admin/owner** role.

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

## Inbound — SIEM detections (unavailable)

The inbound path (a SIEM pushing detections that correlate against the IOC
catalogue and reopen findings) used the retired sensor protocol v1 route and
is unavailable until protocol v2 has a telemetry route (**Planned**). The design
is kept in [siem-ingest.md](../architecture/siem-ingest.md).

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Splunk **Send** test fails | Wrong HEC URL/token, HEC disabled in Splunk, or the endpoint is blocked by the SSRF guard (must be reachable & not a private/blocked target per policy). |
| Nothing arrives in Splunk on real events | Outbound forwards *notifications* — confirm notifications are actually being generated. |
