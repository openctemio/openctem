### Security: threat-intel, validation, program-metrics and cycle figures follow the viewer; dashboards fail closed

- The tenant EPSS and KEV exposure counts, the validation coverage and
  downgrade figures and the program metrics now apply the pentest
  member-visibility rule of the findings list: a pentest finding counts only
  for a member of its campaign, and a draft or in-review one counts for nobody.
  Before, a viewer whose scope covered the tested asset could count (and, by
  differencing, infer) pentest findings of campaigns they were not on.
- `GET /ctem-cycles` and `GET /ctem-cycles/{id}` (and the close and
  scope-refinement responses) omit `charter_evaluation`, which is computed from
  organization-wide metrics, for a restricted viewer without
  `dashboard:aggregate`; the rest of the cycle stays readable.
- The dashboard counts take the `dashboard:aggregate` decision from the
  data-scope enforcer only (one wiring instead of two), and the dashboard,
  attack-path and exposure-chain reads for a caller refuse when the enforcer is
  not wired instead of returning organization-wide data.
