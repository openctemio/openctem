### Added: tool availability from the sensors' manifests

- `GET /api/v1/tenant-tools/availability` lists every catalog tool, plus every tool the organization's sensors report. For each tool it gives the sensors that have it (online and total, with their zones and an exclusion reason when the grant or the local policy stops them), the versions and content versions they report, and a derived status: `ready`, `no_sensor`, `offline_only`, `outdated` or `disabled`. `?zone_id=` limits it to one scan zone. Sensor names are listed only to holders of `sensors:read`; the counts go to everyone who may read the tenant's tools.
- `is_available` on the tools-with-config endpoints is now the same answer: an online sensor that may run the tool. `/{toolId}/with-config` used to always return `false`.
- Tools can carry a minimum version (`min_version`, migration 001150), set on custom tools through the custom tool API. A tool whose online sensors all run an older version is `outdated`.

### Behaviour change: a scan no sensor can run is refused at trigger time

- A trigger (manual, scheduled or quick scan) is refused with `NO_SENSOR_FOR_TOOL` when its scanner, or the tool of one of its workflow steps, has no online sensor that may run it. A zone-pinned scan is judged on that zone's sensors. These jobs used to be queued and expire unclaimed. The error body's `details` name the tool, the step and the sensor counts.
- The trigger refusal codes `NO_SENSOR_FOR_TOOL`, `NO_SENSOR_AVAILABLE`, `TOOL_NOT_FOUND`, `TOOL_DISABLED` and `TOOL_NOT_SCANNER` are now returned in the error `code` instead of `BAD_REQUEST`.
