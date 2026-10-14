### Fixed: a run's seed targets name their inventory asset

- A stage plan recorded its seed targets (`scan_run_targets`, origin `seed`)
  without the asset they are, so a run could not say which assets it
  covered. The seed now names the tenant's asset of that name (an open port
  seed `host:port` matches `host:port:tcp`), in the same transaction. Seeds
  nothing in the inventory names (wildcards, ranges, unknown literals) stay
  without an asset. Rows recorded before this change are not rewritten.
