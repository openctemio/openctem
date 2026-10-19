### Changed: the SLA compliance page reads its numbers in one request

- `GET /findings/stats` takes `sla_breakdown=true` and then also returns `sla`:
  past due, due soon and on track counts, past due by age (up to 7, 8-30,
  31-90, over 90 days; the buckets add up to past due) and past due by
  severity. It runs over the same filter, tenant and data scope as the
  findings list. The SLA page used eight stats requests for these numbers.
