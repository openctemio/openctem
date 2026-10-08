### Fixed: the console states SLA windows from the organization's SLA policy

- The priority-class badge, the finding "Why it matters" panel and the
  priority explanation said P0/P1/P2 = 7/30/60 days and P3 "opportunistic",
  which matched neither the platform defaults (2/5/15/30 days) nor a
  configured policy. They now show the window of the finding's asset (its
  override, else the organization's default policy, else the platform
  defaults), read from the API.
- The pentest finding forms suggested a deadline of 7/30/90/180/365 days by
  severity; the suggestion now uses the severity window of the asset's SLA
  policy (none for informational findings with no SLA).
- A new SLA policy starts from the organization's current windows as the API
  reports them; the web keeps no copy of the defaults.
- `GET /api/v1/sla-policies/default` and `GET /api/v1/assets/{id}/sla-policy`
  return the platform default windows with `is_platform_default: true` and an
  empty `id` when no policy is configured, instead of 404.
