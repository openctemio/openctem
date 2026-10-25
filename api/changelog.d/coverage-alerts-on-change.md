### Changed: coverage alerts are sent on change, with the action to take

- Coverage alerts (gap, no output, keeps failing) are no longer re-sent every 20 hours while a condition holds. Each one is sent when its condition appears, or when its count doubles or halves. A condition that clears and comes back within a day stays quiet. Several changes at once go out as one digest, at most one per organization per day.
- New alert: a capability paused because it cannot run (no scope entry, no sensor, tool missing or not allowed, sensor offline or outdated, a policy) is reported once per reason, with what to do and a link to the scope, sensors or tools page.
- "Keeps failing" is no longer raised for the platform's own DNS checks on single assets; the asset page shows them.
- Migration `003412_asset_coverage_alerts` adds the alert state table. The 20-hour claim keys in `controller_leases` expire on their own.
