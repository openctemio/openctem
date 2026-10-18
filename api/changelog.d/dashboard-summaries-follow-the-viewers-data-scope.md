### Security: threat intel, validation, scan coverage, CTEM cycle and attack-path summaries respect the viewer's data scope

- `GET /threat-intel/stats` (EPSS and KEV past-due counts), `GET /validation/coverage`,
  `GET /scans/coverage` and the `summary` of `GET /attack-surface/attack-paths`
  counted the whole organization for a restricted member, so a member with
  no assets in scope still saw the organization's exposure numbers. They now
  count the findings and assets the caller may see; a viewer with
  `dashboard:aggregate` or full data access gets the organization totals, as on
  `/dashboard/stats`. The attack-path rows stay limited to the caller's scope
  for everyone.
- `GET /ctem-cycles/metrics/trend` is computed per organization and cannot be
  narrowed: a restricted member without `dashboard:aggregate` or full data
  access now gets 403.
