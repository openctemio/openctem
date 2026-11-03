### Changed: platform console Admin activity shows changes by default

- Admin activity and an organization's Activity tab open on "Changes": writes, sign-ins, elevations and refused attempts. Page views and the record written before each change are under "All events", one click away; no row leaves the hash-chained log.
- The organization overview and the user page list recent changes only.
- `GET /api/v1/admin/audit-logs` takes `kind=changes` for that view (any other value lists every row).
