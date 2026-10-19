### Security: every finding status change is recorded and fires its side effects once

- The fix claim, verify and reject actions by id (`/findings/actions/fix-applied`, `/verify`, `/reject-fix`) wrote the status with a plain update: no timeline entry, no workflow event, no assignee notification, no ticket sync. They now write one status-guarded batch with the timeline entry in the same transaction, naming the person.
- One function runs the side effects of a status change (workflow event, assignee notification, proof-of-fix re-check for a fix claim) for every route: status PATCH, bulk status, ticket webhooks, the actions by id and by filter, approved requests (two-person, single-person false positive, self-approval, group exceptions) and VEX statements. Each moved finding gets them exactly once.
- The outbound ticket status push is queued (durable job) in the status write's transaction for every one of those routes, only for the findings the write moved; approvals, the actions and VEX statements queued none before. A move made by a ticket webhook is not pushed back to the ticket.
- Bulk status counts, records and syncs only the findings its guarded write actually moved; a finding that changed in between is reported as "changed since it was read".
- Bulk assign records an `assigned` activity per finding and notifies the assignee once.

### Behaviour change: reject fix by filter reads at most 1000 findings

- `/findings/actions/reject-fix` with a filter now refuses a filter that selects more than 1000 findings, like verify by filter, so its write names the findings it moves.
