### Added: My Work queues in the findings and approvals APIs

- `GET /api/v1/approvals?queue=review` lists the pending finding status requests the caller may still decide (not their own, not signed by them, not on an asset they own; empty without `findings:approve`); `queue=requested` lists the caller's own requests. Both add `queue_counts`, and each row the finding's facts now and `changed_since_request` (for example `kev` when the finding became known exploited after the request).
- The findings filter `related_to` accepts `my_team`: findings assigned to anyone who shares an active group with the caller, or to that group. The data scope still applies.
- `GET /api/v1/findings/quick-views` adds `my_team`, `my_due_soon` (SLA due within 72 hours) and `my_accepted_expiring`.
