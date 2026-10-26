### Fixed: Remediation tasks after a finding delete, dashboard open drill, bulk status notices, epic claim audit

- Deleting a finding or all findings of an asset now re-derives the remediation tasks that held them at once, and the background reconcile also picks a task whose stored member counts differ from its live members, so a task no longer keeps a stale state, count and past deadline.
- The dashboard open-findings figure counts informational findings, so its links (the summary tile and widget drill-downs without a severity filter) now ask the findings list for them and the list total equals the figure.
- A bulk status change (bulk by id or filter, remediation mark fixed, epic claims) now sends each person one summary notice for the batch instead of one notice per finding; a single move still notifies per finding and timeline and audit entries are unchanged.
- A fix claim made by a campaign's Jira epic now records `source=jira_epic` and the Jira account on its audit event.
