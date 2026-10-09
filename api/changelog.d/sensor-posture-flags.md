### Security: unhardened sensors are flagged

- Sensors report their posture: `local_policy.required` on heartbeats and manifests, and the manifest member `posture` (platform TLS pin, tool sandbox and its network confinement) behind the new hello feature `posture`. Both are sanitized to closed values; unknown values are dropped. The posture is display and alert data only and never relaxes a platform check.
- `GET /api/v1/sensors` and `GET /api/v1/sensors/{id}` return `posture`: `local_policy` (`enforced`, `absent_required`, `absent_legacy`, `unknown`), `platform_pin` (`fingerprint`, `ca_file`, `none`, `unknown`), `network_enforced` and `unhardened` (`policy_none`, `pin_none`, `network_unenforced`, `bearer_key`); `local_policy.required` is returned too.
- The Sensors page shows an "Unhardened" tag on flagged sensors and a Security posture block in the sensor details, with one fix per reason.
- The config check `policy.local` accepts code `required_absent` (a sensor that requires a local policy and has none refuses network jobs).
- Gauge `openctem_sensors_unhardened{kind}` and alert `SensorsUnhardened` (warning after 24 hours), with a runbook in `docs/operations/monitoring.md`.
