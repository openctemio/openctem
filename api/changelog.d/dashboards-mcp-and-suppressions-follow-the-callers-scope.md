### Security: dashboards, MCP and suppression rules follow the caller's data scope

- **Dashboards.** The weekly velocity, the executive summary totals, the data
  quality scorecard and the process metrics count the viewer's own scope, like
  `/dashboard/stats` (a restricted member without `dashboard:aggregate` saw
  organization totals). A viewer with `dashboard:aggregate` or full data access
  still sees the organization. The risk-trend history and the program metrics
  are kept for the whole organization: a restricted viewer without
  `dashboard:aggregate` gets an empty trend and a 403 on the program metrics.
- **MCP finding tools.** The by-id read behind `get_finding`,
  `explain_priority`, `list_finding_transitions` and `add_finding_comment` makes
  the same decision as the REST route guard. A full-data role no longer reads
  the findings of a private bug-bounty program it is not a member of.
- **Suppression rules.** A rule bound to an asset is read, edited, approved and
  deleted only by a caller whose scope holds the asset, and the list leaves out
  the others. An organization-wide rule needs full data access to create, edit,
  approve, delete or mark reviewed (a restricted member with
  `findings:suppressions:approve` could approve a rule that closes findings on
  every asset). The active-rules list of the user route (`/suppressions/active`)
  leaves out rules bound to assets outside the caller's scope; the sensor route
  is unchanged.
