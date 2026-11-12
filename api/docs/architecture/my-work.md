# My Work

My Work (`/my-work` in the console) is the personal start page: what waits on
the signed-in person, their team, and their requests. Every queue is a view on
the caller's own rows, read through the same caller-scoped endpoints as the
rest of the console, so a count always equals the total of the list it opens.

## Queues

| Queue | Rows | Source |
| --- | --- | --- |
| Assigned to me | open findings assigned to me, to one of my groups, or on an asset I own | quick view `my_queue` (`related_to=me`) |
| My team | open findings assigned to anyone who shares an active group with me, or to that group | quick view `my_team` (`related_to=my_team`) |
| Due soon (chip) | my open findings whose SLA deadline is within 72 hours, overdue included | quick view `my_due_soon` |
| Awaiting my review | pending finding status requests I may still decide | `GET /api/v1/approvals?queue=review` |
| Requested by me | the finding status requests I made | `GET /api/v1/approvals?queue=requested` |
| Acceptances expiring | accepted risks of mine that end within 30 days | quick view `my_accepted_expiring` |
| My tasks | open remediation tasks assigned to me or to one of my groups | the remediation task list with `assignee=me` |

The quick views (`GET /api/v1/findings/quick-views`) carry each view's
`params`, the `GET /findings` query string that lists it; the count and the
list compile the same params in the same caller scope.

## Approval queues

`GET /api/v1/approvals?queue=review|requested` keeps the list's tenant, data
scope and pentest visibility, and adds:

- **review**: pending requests the caller may still decide. The caller holds
  `findings:approve`, did not make the request, has not signed it yet, and
  does not own the finding's asset (the approval policy never lets an owner
  decide). A request of a group exception is decided with its group and is
  left out, and so is one past its decide-by time. Without `findings:approve`
  the queue is empty.
- **requested**: the caller's own requests (filter with `status`).
- `queue_counts`: the pending count of both queues, in the same scope.
- On each row, `finding` (severity, priority class, KEV, EPSS, asset name now)
  and, for a pending request, `changed_since_request`: the approval policy's
  class reasons that hold now and did not at request time (`kev`,
  `severity_critical`, `exploit_validated`, ...), compared with the
  evaluation the request stored. The approver sees that a finding became known
  exploited after the requester asked.

A queue needs a signed-in person: an API key or a platform caller gets 400.

## Inbox summary

`GET /api/v1/me/inbox/summary` counts every queue of the signed-in person in
one call, for the sidebar's Inbox count and the tab counts:

```json
{
  "queues": {
    "assigned": 5, "team": 9, "due_soon": 2, "review": 3,
    "requested": 2, "expiring": 1, "tasks": 1, "ready_to_close": 1
  },
  "total": 13
}
```

- **Same predicates as the lists.** The endpoint compiles no filter of its
  own. The finding queues are counted by the quick-view code
  (`CountQuickViewsOf`, the four views `my_queue`, `my_team`, `my_due_soon`,
  `my_accepted_expiring`, one statement); review and requested by the
  approval queue counter (`CountApprovalQueues`, the `queue_counts` of
  `GET /approvals?queue=`, one statement); tasks by the remediation task
  list's own count (`CountTasks`, `assignee=me` over the open states `open`,
  `in_progress`, `verifying`, `on_hold`); ready to close by the closure
  proposal count (`GET /findings/closure/proposals`). Each runs as the caller,
  so a count equals the total of the list it opens; `inbox_summary_db_test.go`
  checks that per queue for an owner and a scoped member.
- **Total** = assigned + review + requested + expiring + tasks +
  ready_to_close, over the queues present. My team is other people's work and
  Due soon is part of Assigned to me, so neither is in it.
- **Queues follow permissions.** A queue the caller cannot use is absent from
  `queues` (its tab is left out), never 0:

  | Queue | Needs |
  | --- | --- |
  | assigned, team, due_soon, expiring, requested | `findings:read` |
  | review | `findings:read` and `findings:approve` |
  | ready_to_close | `findings:read` and `findings:verify` |
  | tasks | `findings:remediation:read` and the remediation module |

  Without `findings:approve` the review condition is the list's empty one
  (it matches nothing) and the key is absent. Ready to close needs the permission that
  decides a proposal, as the sidebar badge does.
- **Caller.** Tenant, user and permissions come from the session; the route
  takes no parameter. An organization API key or a platform caller (no
  person) gets 400. A delegated credential of a person reads on that
  person's own scope rows, as every list does.
- **Cost.** At most four count statements plus the scope lookup, the same
  number whatever the data size (`TestReadQueryBudget` holds the route to its
  entry in `testdata/read_budget.json`). The route runs under the heavy-read
  limiter like the quick views; a finding count past its 5 s limit answers
  503. The response is `Cache-Control: no-store`: the count changes after
  each decision and a shared browser must never show one person's counts to
  the next.

Key files: `internal/app/inbox/service.go`,
`internal/infra/http/handler/inbox_handler.go`,
`internal/infra/http/routes/inbox.go`.

## Security

- The queue filters only narrow the caller's existing approval list; they
  never widen it. Deciding still goes through `POST /approvals/{id}/approve`
  (findings:approve, step-up, the approval policy re-evaluated now, four-eyes)
  and `/reject`.
- `related_to=me` and `related_to=my_team` bind the acting user; a user-less
  key and a system caller are refused. My team adds no visibility: a
  teammate's finding outside the caller's data scope stays hidden, an ended
  group membership and an inactive group do not count, and a group of another
  tenant reaches nothing.

## Console

`web/src/features/my-work/` (page `app/(dashboard)/my-work`):

- One tab per queue with its count; a tab the caller cannot use is left out
  (Awaiting my review without `findings:approve`, My tasks without
  remediation read). The tab is in the URL (`?tab=`); `?due=72h` turns on the
  Due soon chip of Assigned to me.
- Finding queues list the quick view's own `params` (nearest SLA first on
  Assigned to me); View all opens the same list on Findings; Triage these and
  the header's Triage button open triage mode on the view (Triage needs
  `findings:status`).
- The SLA cell is the shared `SlaDueChip` (also on Findings): the status, the
  time left or past due (hours under two days), and a marker when the policy's
  KEV cap set the deadline.
- Awaiting my review decides in place through the shared approval decision
  dialogs (`useApprovalDecision`, also on the approvals inbox): Approve asks
  for a recent sign-in, Reject asks for a reason. Keys while a row has focus:
  `j`/`k` move, Enter opens the finding, `a` approves, `r` rejects.
- Requested by me can remind the approvers or withdraw a request.
- An empty queue names one next step (findings due in 72 hours, triage, your
  own findings) and a secondary link.
- A hard load sends at most six API requests (the session bootstrap, the
  support-access banner, the quick views, one approval queue page, the task
  count, the open tab's rows).
