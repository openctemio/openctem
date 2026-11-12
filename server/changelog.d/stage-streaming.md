### Behaviour change: chained scan steps start on each finished task of their predecessor

- A chained workflow step no longer waits for its whole predecessor step: it takes the results of each
  finished predecessor task as that task's report is ingested, and a step a successor streams from is cut
  into about four smaller tasks. Every target still passes the per-hop gate (type contract, hop limit,
  fan-out caps, scope exclusions, act scope, zone, ownership and tier) and reaches the sensor in a signed
  job with an explicit target list. A streamed step finishes after its predecessor; coverage and closing
  stay decided per command (RFC-137).
- Migration `20261031062911_stage_streaming` adds the stream columns to `scan_run_stage_plans` (add-only).
- `GET /api/v1/scan-runs/{id}/stages` adds `streamed`, `stream_open`, `waves` and `first_dispatch_at`;
  workflow settings add `stage_barrier`.
- Metrics: `scan_stage_stream_waves_total`, `scan_stage_time_to_first_successor_seconds`,
  `scan_stage_barrier_wait_saved_seconds`.
- **Upgrade note:** on by default. `SCAN_STAGE_STREAMING=false` restores the barrier for every workflow;
  `stage_barrier: true` in a workflow's settings restores it for that workflow.
