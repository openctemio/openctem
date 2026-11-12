### Added: a readiness checklist for every sensor

- `GET /api/v1/sensors/{id}/readiness` (`sensors:read`) lists what still stops a sensor from scanning, in fix order: online, trusted, host allows private networks, host kill switch, networks assigned, networks in scope (or waiting for approval), tool confinement on the host. Each item has one fix and the permission it needs.
- The checklist shows on the sensor sheet, at the end of Add sensor, and in New scan for the sensors of the chosen zone. Promote, Add to scope, the host line to copy, Assign networks and the host requirements guide are one click away.
