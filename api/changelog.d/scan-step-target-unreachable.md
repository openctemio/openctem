### Behaviour change: a scan step whose targets were unreachable is no longer "completed, 0 results"

- A sensor now reports per-target reach with each command result
  (`metadata.reach`, `unreached_targets`; RFC-089). When the sensor reached
  none of a step's targets (no route, a firewall refused it, every attempt
  timed out, the names did not resolve) and found nothing, the step **fails**
  with the new code `TARGET_UNREACHABLE` instead of completing with zero
  results, which read as "nothing exposed". When it missed only some targets,
  the step and the run end **partial** with a per-class summary.
- Users will see failed or partial steps (and runs) where they used to see
  completed runs with no results. The cause is where the scan ran from: route
  the targets to a sensor that can reach them (a zone, or another sensor).
- `TARGET_UNREACHABLE` is never retried automatically. Sensors that send no
  reach summary keep today's outcome; their failure text such as "network is
  unreachable" or "no route to host" is now classified as `TARGET_UNREACHABLE`
  instead of a retryable `COMMAND_FAILED`, and a sensor may send the code in a
  structured fail (`POST /api/v2/sensor/commands/{id}/fail`).
- The reach data is sensor-supplied: counts are clamped, at most 20
  unreached targets are kept per task, and every string is cleaned to one
  bounded line. No migration.
