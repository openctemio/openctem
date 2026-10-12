### Security: sensor control-stream wakes and opens are rate-limited

- Control-stream wakes are coalesced per tenant and per sensor: at most one
  delivery per 500 ms on each replica, the rest folded into one delivered at
  the end of the interval (delayed, never lost). A tenant releasing or
  refusing commands in a loop no longer makes every stream of the tenant on
  every replica re-authenticate and re-read the doorbell each time.
- The cross-replica wake publish queue gives each tenant at most 32 of its
  1024 slots; a tenant's excess folds into one tenant-wide wake, so one
  tenant cannot crowd out another's wakes. New metric
  `openctem_sensor_wakes_coalesced_total{reason}` (`tenant_quota`,
  `queue_full`).
- Protocol v3 `Subscribe` opens are limited per sensor (6 per minute, burst
  10, per replica) and refused with `ResourceExhausted` before any database
  work. New metric `openctem_sensor_stream_opens_refused_total{reason}`
  (`rate`, `concurrent`).
- **Upgrade note:** none.
