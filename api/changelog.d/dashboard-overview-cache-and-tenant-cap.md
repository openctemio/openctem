### Changed: the dashboard overview is reused briefly and capped per organization

- `GET /api/v1/dashboard/overview` runs twelve tenant-wide reads. Identical
  concurrent calls from the same session now share one computation, and the
  result is reused for 15 seconds. Nothing is shared between users or
  sessions, so each caller still sees only what its own permissions and data
  scope allow.
- One organization runs at most four overview reads at a time. A burst of
  dashboard loads in one organization queues instead of taking every database
  connection. On a 525k-finding tenant, 50 concurrent loads used to time out
  (and, before the timeout fix, crash the API). Ten cold loads now finish in
  5.6 s and repeat loads in under 100 ms.
- The tenant-wide aggregate endpoints (dashboard metrics, finding and asset
  stats, finding groups, threat-intel stats, attack-surface stats, paths and
  chains) run at most four at a time per organization. Extra requests wait,
  and a request that gives up waiting gets 503 with `Retry-After`.
