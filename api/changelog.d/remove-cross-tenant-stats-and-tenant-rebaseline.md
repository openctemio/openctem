### Security: no cross-organization dashboard total, and no audit-chain rebaseline from the organization

- `GET /api/v1/dashboard/stats/global` is removed. It summed assets and
  findings over every organization in the caller's token, so the other
  organizations' IP allowlist, SSO enforcement, modules and data scope were
  never applied. Nothing in the web console called it. `GET /api/v1/dashboard/stats`
  (the current organization) is unchanged.
- `POST /api/v1/audit-logs/rebaseline` is removed. The audit hash-chain makes
  a privileged insider's changes evident, and the organization's owner is
  that insider. The platform operator rebaselines from the admin console
  (`POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline`), which also
  checks that every break is explained. `GET /api/v1/audit-logs/verify` stays.
- A new test fails if a tenant-plane route reaches an admin-only action
  (the rebaseline, or a read over every organization in the token).
- **Upgrade note:** both paths answer 404 or 405. Ask the platform operator
  for a rebaseline.
