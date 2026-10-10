### Added: scan approval requests and the run gate

- When scan approval is On or Strict, a scan the organization's rules catch
  runs only under an approval of its current definition (targets and
  selectors, intensity, tools or workflow, schedule, sensor placement and
  zone). Runs of an approved definition need nothing more; a change needs a
  new approval with the diff shown. Manual, scheduled, quick and retried
  runs all pass the gate (a scheduled run without approval is recorded as
  blocked). RFC-072 §8.
- New permission `scans:approve` (owners and administrators). Routes:
  `POST /api/v1/scans/approval-preview`, `GET/POST /api/v1/scans/{id}/approval`,
  `POST /api/v1/scans/{id}/emergency-run` (owner or administrator, step-up,
  1-24 hours, audited critical), `GET /api/v1/scan-approvals`, and
  `approve`, `reject`, `self-approve` (sole owner with an authenticator
  code), `remind`, `cancel`. The scan list returns `approval_status`.
- Migration `001831` adds `scan_approval_requests` and the permission.
