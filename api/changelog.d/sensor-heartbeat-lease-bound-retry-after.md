### Changed: sensor heartbeat maximum follows the command lease; jittered Retry-After

- The longest heartbeat interval the platform advises is now derived as
  `min(offline mark / 2, SENSOR_COMMAND_LEASE / 3)`;
  `SENSOR_HEARTBEAT_MAX_INTERVAL` can only lower it. Raising the lease, the
  offline mark or any heartbeat setting can no longer let a sensor that holds
  a command heartbeat too rarely to renew its lease, which re-queued the
  command and ran it twice. The defaults are unchanged (45 s).
- When the doorbell query is slow (platform under load) the doorbell advises
  that maximum interval.
- A 429 from the sensor routes now carries a `Retry-After` computed from the
  refused bucket's refill time plus up to 50 % jitter, bounded to 1 s - 5 min,
  instead of a constant 1 s, so refused sensors do not all retry in the same
  second. Limits themselves are unchanged.

### Removed: SENSOR_HEARTBEAT_LOADED_INTERVAL

- The setting never took effect (it was always clamped to 45 s). Remove it
  from your environment; it is ignored.
