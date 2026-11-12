### Added: Add sensor asks what the sensor will scan

- Sensors, Add sensor first asks whether the sensor scans internet-facing targets, internal networks or both. For internal networks (or both) the install command carries `SENSOR_ALLOW_PRIVATE_TARGETS=1` with a comment that explains it, so the host owner no longer edits the environment and restarts the sensor before an internal scan can run. An internet-only sensor never gets the switch.
- For internal networks the command can also restrict the host to the listed private ranges (`SENSOR_ALLOWED_RANGES`, opt-in).
- `POST /api/v1/sensors/install-templates` takes `purpose` (`internet`, `internal`, `both`) and `allowed_ranges` (private ranges, `internal` only); `GET` takes `purpose`.
