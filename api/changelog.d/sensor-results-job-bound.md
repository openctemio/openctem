### Security: sensor results stay inside the job's targets and cannot choose their channel

- A report bound to a scan or retest command whose targets name a host now
  creates or changes names, addresses, services and web applications only at
  or under the job's target names, at its target addresses and ranges, or at
  addresses an in-bound asset of the same report resolves to. Anything else
  is dropped with its findings, counted (`sensor_results_outside_job_total`),
  shown on the receipt (`outside_job_targets`) and audited
  (`sensor.results_outside_job`). Before, only address-range scans dropped
  out-of-target assets.
- The channel of a sensor's findings (`ingest_channel`) is now set by the
  platform: `collector` for a collector sensor, `scanner` for any other. A
  report's `metadata.source_type` can no longer file a sensor's findings as
  `manual` or `integration`. Findings already stored keep their channel.
