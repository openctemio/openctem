### Fixed: priority and SLA follow classifier inputs at once

- A finding's CVE, catalog link, CVSS score, internet or network accessibility, exposure vector, data exposure risk and compliance impact, an asset's CIA impact ratings, and an asset's owners (added, removed or moved) did not queue a priority recompute, so a changed priority and SLA deadline waited for the daily reconcile (up to about 24 hours). They now queue the asset at once through database triggers (migration `priority_queue_input_triggers`, number 002945). Open findings only; a write that leaves a value unchanged queues nothing.
- The columns the priority worker writes itself (reachability, EPSS, KEV, SLA) are not watched, so a pass does not re-queue itself.
- A guard test lists every `PriorityContext` input and what requeues the asset when it changes, so a new input without a trigger fails the test. It records one input that still waits for the daily reconcile: the threat-model signal.
- Trigger DDL only: no backfill, safe on populated tables; the down migration restores the previous trigger definitions.
