### Behaviour change: remediation campaigns hold tasks; what a campaign tracked becomes its tasks

- A finding is in at most one active work unit (the primary membership of a remediation task), and a campaign is a
  programme of tasks. Migration `003050_remediation_campaigns_hold_tasks` turns the open findings each running
  campaign (draft, active, paused, validating) tracks through its finding filter into tasks of that campaign: one
  task per campaign (title = campaign name, owner = the campaign's assignee while still an active member, and its
  team); a task already holding a finding joins the campaign when it has none; a finding claimed by two campaigns
  goes to the one furthest along, then the oldest. Completed and canceled campaigns are not converted.
- Campaigns whose filter named only severities, sources, statuses or search text tracked nothing and now hold no
  task: add tasks to them.
- Every converted campaign has an audit row (action `remediation_campaign.migrated`: findings moved, tasks joined,
  each conflict and the original filter); tasks that joined a campaign or kept another campaign's claim show it on
  their timeline; owners and admins get one notice.
- **Upgrade note:** none. The campaign filter is not changed; the down migration deletes the converted tasks and
  everything done on them since.
