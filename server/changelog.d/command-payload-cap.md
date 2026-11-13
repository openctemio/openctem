### Fixed: a command payload over 4 MiB is refused at creation

- A sensor reads at most 10 MiB from one commands poll answer, and a claim adds delivery fields and the signed job to a command. One oversized command stopped a sensor's intake until the sensor failed it (sdk-go: an oversized commands-poll answer no longer stops all intake). Every command is now built through one check that refuses a payload over 4 MiB with `COMMAND_PAYLOAD_TOO_LARGE` (a validation error) instead of storing it. Nothing is truncated or split silently; the scan planner already splits targets into jobs far under the cap.
- New metric `command_payload_refused_total`.
- **Upgrade note:** a script or integration that creates commands with a payload over 4 MiB now gets `COMMAND_PAYLOAD_TOO_LARGE` instead of a stored command that stalled its sensor; split the work into smaller jobs.
- Docs: server/docs/architecture/job-dispatch.md ("Payload size")
