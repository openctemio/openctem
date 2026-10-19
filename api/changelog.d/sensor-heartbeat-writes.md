### Behaviour change: heartbeats renew command leases only when needed, and only a heartbeat brings a sensor back online

- A heartbeat renews a held command's lease once less than `max(lease / 2, 2 × interval + 10 s)` is left, instead of on every beat. A busy sensor beating every 5 s now writes its held commands about every 90 s instead of every 5 s; a lost heartbeat still never lets a lease run out.
- A heartbeat that repeats the same progress for a command no longer rewrites the command row.
- A poll or an upload no longer sets the sensor's `health` to `online`: it still counts as proof of life (`last_seen_at`), but only a heartbeat brings a late, stale or offline sensor back online, with its deadline, connect event and audit entry.

### Removed: legacy sensor health checker

- The legacy sensor health checker and its settings are removed; the sensor health controller owns liveness (it already did, the checker was off by default). The unused Redis sensor state store is removed too.
- **Upgrade note:** unset `WORKER_HEALTH_CHECK_ENABLED` and `WORKER_HEALTH_CHECK_INTERVAL` if you set them: startup refuses to run while either is set.
