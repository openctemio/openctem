### Added: benchmark posture, controls and control history reads

- `GET /api/v1/findings/compliance/benchmarks` (pass rate per benchmark over the caller's assets, or one asset), `GET /api/v1/findings/compliance/benchmarks/{key}/controls` (a benchmark's controls, failed first), `GET /api/v1/findings/compliance/benchmarks/{key}/assets?control=` (one control's state per asset with its evidence and finding) and `GET /api/v1/findings/{id}/compliance-history` (every change of the control a finding fails). All need `findings:read` and run in the caller's data scope.
