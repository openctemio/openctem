### Added: Jira issue type per kind of issue, custom types included

- A Jira integration chooses the issue type of findings, remediation tasks and campaign epics separately (Settings → Integrations → Ticketing → Configure → Issue types), from the live list of its default project, stored by id and name (`config.ticketing.issue_types`). A suggestion picks a type named like "Security Finding" or "Remediation Task".
- Remediation task issues are created from the published task field mapping of their type and move along its workflow; every status change, inbound and outbound, uses the mapping of the issue's own issue type and kind, so two types with different workflows in one project are no longer mixed.
- Saving an issue type is checked with Jira: the type must exist in the default project, must not be a sub-task type, and every required field must be filled (built-in or by a published field mapping); the save is refused otherwise, or when Jira cannot be reached.
- A create Jira refuses for named fields marks the field mapping drifted, or records the refusal on the integration for that kind (shown on the Configure dialog, cleared by the next success); the error names the field ids.

### Behaviour change: the single ticketing issue type is replaced

- Migration `ticketing_issue_types` moves `config.ticketing.issue_type` into `issue_types.finding` and `issue_types.task` and removes the key. An integration that never set a type now files remediation tasks as `Task` (was `Bug`); findings stay `Bug`, campaign epics `Epic`.
- **Upgrade note:** API code from before this release reads the new shape with the stock types; stop the old API before the migration runs, as for any release.
