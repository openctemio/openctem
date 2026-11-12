### Security: late results of a superseded run are refused

- A sensor whose command-bound report was refused because the platform took the run back sends it again without the command (sdk-go: late results name the command and lease epoch they were made for). Until now the platform took such a report as an ordinary unsolicited push, so a superseded run's results could create and refresh findings after the run that replaced it.
- The v2 receiver now reads `X-OpenCTEM-Late-Command` and `X-OpenCTEM-Late-Lease-Epoch` on an unbound PUT or commit. When the named command, looked up in the sensor's own tenant only, was claimed again after the stated epoch or is no longer held by the sensor, the report is refused with the new final problem `409 lease-superseded` and nothing is stored. Any other late report is taken as an unsolicited report, as before. Another tenant's command, an unknown id and a malformed header are treated exactly like an absent header.
- Protocol v3: additive optional fields `late_command_id` and `late_lease_epoch` on `PutResultRequest` and `CommitResultRequest`.
- New metric `ingest_late_reports_total{outcome}`.
- Docs: server/docs/architecture/sensor-result-binding.md ("Late reports")
