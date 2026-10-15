### Behaviour change: scoring changes recompute open findings from that moment; closed findings stay frozen

- Every asset risk score and finding priority now stores the scoring version it was computed with (`assets.risk_version`, `findings.priority_version`). A version is a `scoring_changes` row: one per platform model version and one per change of a tenant's risk scoring settings, priority rules or SLA policies, recorded by database triggers (migration 002190).
- A change queues the affected assets in the new durable `finding_priority_queue` in the same transaction; the `finding-priority` worker recomputes the priority and SLA deadline of their **open** findings, tenant-fair. Closed findings are no longer reclassified: they keep the class and deadline they had when closed, so closed-period metrics no longer change after the fact.
- The recompute now re-reads EPSS and KEV from the catalogs, so intel that changed since a finding was ingested is applied.
- New findings, reopens, severity changes, asset criticality, exposure and crown-jewel changes, and business unit and service changes queue the asset. The 12-hour whole-tenant sweep and the in-memory queue are removed; a daily reconcile (and one at start-up) queues stale findings at once and the rest behind events.
- Metrics: `openctem_finding_priority_queue_depth`, `..._queue_oldest_seconds`, `..._checked_total`, `..._changed_total`.
- **Upgrade note:** none. After deploy the start-up reconcile recomputes every open finding once in the background.
