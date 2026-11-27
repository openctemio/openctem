### Fixed: the finding page names the requester of an approval and says how a closed finding was closed

- The approval band on a finding named a current member "Former member": the finding's approvals
  (`GET /api/v1/findings/{id}/approvals`) now carry `requested_by_name` like the approvals list, for current
  members of the organization only.
- A closed finding no longer shows an SLA countdown, a "Resolved" date for every closure or Proof of fix: it
  says "Marked false positive", "Risk accepted" until its end date, "Duplicate of" with a link, or "Resolved",
  and shows Proof of fix only when it was resolved by a fix.
- The band's Approve and Reject are the outline decision controls of the approvals inbox, named by the
  request, so the page header keeps its one main action.
- In Vietnamese, the activity summary ("1 event"), invitation roles and member dates follow the language.
- Docs: web/docs/finding-detail.md
