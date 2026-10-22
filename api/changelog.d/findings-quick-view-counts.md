### Added: Quick-view counts for the findings list

- `GET /api/v1/findings/quick-views` (needs `findings:read`) returns the list's built-in views with the
  caller's count of each: active, needs triage, my queue, SLA breached, pending approval, accepted and
  expiring within 30 days, closed. Each view carries the `GET /findings` query string that opens it, and
  its count equals that list's total for the same caller (tenant, data scope and pentest membership
  applied). One statement with a 5 s limit; 503 when it runs out.
- New findings filters: `pending_approval=true|false`, `acceptance_expires_at_{gte,gt,lte,lt}` and
  `state=closed` (fixed and dispositioned together).
- Relative times in filters may now point ahead: `P30D` or `+P30D` is thirty days from now; `-P30D` is
  still thirty days ago.
