### Added: dispatch metrics: claim latency, queue depth by stage and wait reason, wait until claimed

- `command_claim_duration_seconds{mode}`, `command_claim_wait_seconds{class}` and `command_claim_skipped_total{reason}` (`local_policy`, `no_slot`, `scope_changed`, `window_hold`, `program_hold`, `taken`) show how long claims take, how long work waits for a sensor and why poll candidates were not handed out.
- `openctem_command_queue_depth{stage,tool,class,wait}` counts pending commands by stage, platform tool, priority and wait reason (`ready`, `host_busy`, `scheduled`); `openctem_command_queue_tenants` and `openctem_command_queue_top_tenant_pending` give the tenant dimension without tenant identity. A tenant's own tool is reported as `_custom`.
- The "OpenCTEM operations" Grafana dashboard has a new Dispatch row with these series.

### Fixed: `command_claims_total{mode="claim_n"}` was never incremented

- The poll's claims (claim-N, the path every current sensor uses) are now counted, one per command handed out.
