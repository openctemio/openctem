### Security: shared sensor access policy, held behind the rollout gate

- Whether an organization may send scans to shared sensors is now one policy (RFC-100 §5). Every layer must allow it:
  - the instance switch `shared_sensors.enabled` (off by default);
  - the instance administrator's allow or deny for the organization. An organization without a decision follows `shared_sensors.new_orgs` (on by default), and a deny always wins;
  - the organization owner's opt-out (off by default).
- Any layer that cannot be read refuses. Refusals name the real reason and never mention an edition.
- Admin console, System > Platform scanning, "Shared sensors", and `GET/PUT /api/v1/admin/settings/shared-sensors`. The decision for one organization is at `GET/PUT /api/v1/admin/tenants/{tenantId}/shared-sensors`. Any administrator reads; a change needs a super admin, a reason and a fresh authenticator code. Each change gets a critical admin audit row and the other administrators are emailed.
- Organization settings, Security, "Never use shared sensors", and `GET/PUT /api/v1/organization/settings/shared-sensors`. The owner or an administrator reads it; only the owner changes it, and the change gets a tenant audit row (`tenant.shared_sensors_updated`).
- Shared sensors stay unavailable on every deployment until the shared claim path and per-job isolation land. Every organization is refused with "shared sensors are not available yet", and the console refuses to turn the switch on (409 `SHARED_SENSORS_NOT_READY`).
- Migrations `002451_shared_sensors_access` (nullable `tenants.shared_sensors_access`, CHECK added `NOT VALID`) and `002452_shared_sensors_access_validate`. Additive; no upgrade step.
