### Behaviour change: unreachable and skipped targets no longer make a run partial

- A target that did not answer (timeout, no route, DNS) or that the sensor's local policy skipped is a fact about the target, not lost work: the step and the run complete, and the counts are recorded (`unreachable_target_count`, `skipped_target_count` in the run context and the step output). `partial` stays for unfinished work: coverage gaps, targets a result left unfinished, targets no zone or sensor could place, failed batches.
- A step that tried more than one target and reached none of them still fails as `TARGET_UNREACHABLE`; a single target that did not answer completes with one unreachable.
- Success rates (completed over finished runs) stop counting dead hosts as failures. The coverage ledger is unchanged: an unreachable target is still not settled as covered, now also for tasks that report no per-target outcomes.
- The run API (`GET /scan-runs`, `GET /scan-runs/{id}`) adds `unreachable_target_count` and `skipped_target_count`.
