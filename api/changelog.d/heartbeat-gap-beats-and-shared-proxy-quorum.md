### Fixed: heartbeat history gap_beats, and shared proxy endpoints need two sensors

- The sensor heartbeat history counted every heartbeat that had a previous
  one as a gap (`gap_beats` always equalled `beats` minus the first), so the
  table said nothing about late heartbeats. `gap_beats` now counts heartbeats
  whose gap exceeded 1.5 intervals (the `heartbeat_late` rule); the old count
  moves to the new `prev_beats` column (migration
  `20261030090000_sensor_heartbeat_prev_beats`), the divisor of the average
  gap.
- A proxy endpoint that jobs of several sensors went through in the last 30
  minutes is quarantined from task reports only when at least two distinct
  sensors reported faults through it, so one sensor's own network problem can
  no longer take a shared endpoint away from everyone. An endpoint used by a
  single sensor keeps the earlier rule.
