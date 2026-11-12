### Added: sensors that check no job signature are flagged, with the fix

- A sensor reports how it checks the platform's job signatures (manifest posture `jobs.signed`). The sensor API now returns it as `posture.signed_jobs` (`required`, `verified_when_present`, `off`, `unknown`), and a sensor with signed jobs `off` is flagged unhardened with the new reason `jobs_unsigned`: such a sensor trusts every job and refuses jobs that need platform secrets. The console shows the reason with its fix (pair the sensor again, or set `SENSOR_JOB_SIGNING_ROOT`), in English and Vietnamese, and the `openctem_sensors_unhardened` gauge counts it.
- A job a sensor refused with the rule `secrets_unverified` now fails with a reason that says so and names the same fix, instead of the built-in deny list explanation.
- Docs: server/docs/architecture/sensors.md ("Security posture")
