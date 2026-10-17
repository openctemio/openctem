### Security: finding approval decisions are in the audit log, including refused self-approvals

- Requesting, approving, rejecting and cancelling a false-positive or
  accepted-risk request each write an audit row (`finding_approval.requested`,
  `.approved`, `.rejected`, `.canceled`; resource type `finding_approval`)
  with the actor, the finding, the requested status and the dates. The
  justification text stays on the request and the timeline, not in the audit
  metadata.
- A requester who tries to approve their own request is refused as before and
  the attempt is now recorded (`finding_approval.self_approval_refused`,
  result denied, severity medium), so such attempts can be reviewed.
- Expired requests were already audited (`finding_approval.expired`).
