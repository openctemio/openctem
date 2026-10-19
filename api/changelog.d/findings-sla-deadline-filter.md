### Added: filter and sort by the SLA due date

- `GET /findings`, `/findings/stats`, `/findings/export` and the saved filters
  take `sla_deadline_gt`, `_gte`, `_lt`, `_lte` (RFC 3339, a date or `-P7D`
  style duration) and sort by `sla_deadline`. With `sla_status` this counts
  past-due findings by age, which the SLA compliance page uses so its numbers
  come from the server over the same population as the Findings list.
