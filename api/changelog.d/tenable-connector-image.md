### Added: the Tenable.sc connector image and its grant profile

- The Tenable.sc connector now runs as its own image, `ghcr.io/openctemio/connector-tenable` (openctemio/connector-tenable), paired like a sensor; the sensor no longer carries it. The connector dialog shows the run command and points to the image's setup guide (en, vi).
- New sensor grant profile `scan-connector` (or `scan-connector:<tool>`): job types `connector_sync` and `connector_scan`, tier ceiling T1, no credentials, no push ingest, zone-bound. Before it, no profile allowed `connector_scan`, so a connector sensor needed a custom grant. A connector at trust level New receives syncs only until an administrator trusts it. The grant refusal of a connector sync or scan names the profile.
- The connector dialog's text goes through the translations.
