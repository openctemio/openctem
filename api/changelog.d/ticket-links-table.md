### Added: ticket links as their own records

- New `ticket_links` table: one row per link between a finding or a
  remediation task and a Jira issue, with the integration that owns the issue,
  the issue key, the project, the link's role and state (active, unlinked,
  deleted) and who created it (platform or person). The integration, the
  finding and the task are tenant-scoped foreign keys, so a link can never
  pair one organization with another's integration or finding.
- Existing Jira browse URLs on findings and campaign tickets whose site
  matches one of the organization's Jira integrations are copied in.
- Upgrade note: a unique index on `remediation_campaigns (id, tenant_id)` is
  added (a small table).
