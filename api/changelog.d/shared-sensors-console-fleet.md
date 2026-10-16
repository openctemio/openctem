### Added: console page for shared sensors (fleet, queue, audited job view, pause, resume, retire)

- Console > System > Shared sensors (`/api/v1/admin/shared-sensors`). Any administrator sees:
  - the instance sensors: name, region, status, health, version, tools, current jobs, last seen;
  - queued and running shared jobs per tool lane;
  - per-organization counts (organization names only for super and operations administrators; a read-only administrator gets opaque ids);
  - job metadata: organization, type, tool, state, shared sensor, times.
  No payload, targets, result or error text is ever listed.
- `POST /api/v1/admin/shared-sensors/jobs/{job_id}/view` shows one job's targets and logs. It needs a super or operations administrator and a reason, and is rate-limited. A high admin audit row (`shared_sensor.job_viewed`, with the organization and the reason) is written before anything is returned. Results and findings are never shown.
- `POST /api/v1/admin/shared-sensors/{sensor_id}/disable|enable|revoke` needs a super admin, a reason and a route-level step-up, and writes a critical admin audit row before the status changes (if the row cannot be written, the action fails and nothing changes). It only acts on instance sensors (an organization's sensor answers 404). Pause stops new jobs while held jobs finish; retire revokes the sensor, and it cannot be resumed (409).
- No migration.
