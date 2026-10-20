### Security: the owner of a remediation task sees exactly the task's findings, and only the fix workflow

- The owner of a live task (the user, or an active member of the owner team) can open the task's findings and a minimal asset card even when the findings' assets are outside their data scope, and the task is no longer a 404 or read-only for them. They never see the asset's other findings, a finding on a hidden private-program asset, or a pentest finding outside their campaigns. The relation is computed on each request, so it ends when the owner changes, a finding leaves the task, the task closes, or the team membership ends, expires or is suspended.
- On those findings they can comment, start work, go back to confirmed, claim the fix, add a manual evidence note and request a proof-of-fix or retest. False positive, accepted risk, resolve, severity, classification, assign, approvals, tickets and delete still need the finding in their own scope; the status menu shows them blocked (`not_in_scope`). API keys never get the relation.
- Each status move made only through the relation is audited as `remediation_task.owner_moved_finding`.

### Fixed: "Mark fixed" on a task no longer refuses every finding that is not assigned to the clicker

- The task owner is now a fix owner of the task's findings (with `findings:fix_apply` and a note), next to the finding's assignee, an assigned team member and the asset owner. The claim used to be refused as `not_fix_owner` for each unassigned finding.
- Two partial indexes on live remediation tasks (by user owner and by team owner) back the lookup.
