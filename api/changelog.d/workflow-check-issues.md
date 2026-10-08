### Changed: checking a scan workflow draft reports every issue, by step

- `POST /api/v1/scan-workflows/verify` returns 200 with every issue of the
  draft, each anchored to its step and field (`node`, `field`) with a `fix`.
  It used to stop at the first step problem with a 400, so the builder showed
  nothing while the user edited a step with a bad setting. `errors` block a
  save; `warnings` do not.
- New warnings: a pinned tool no online sensor offers (`TOOL_UNAVAILABLE`),
  and a capability none of whose tools (the preferred ones when listed) is on
  an online sensor (`NO_SENSOR_FOR_CAPABILITY`).
- The builder shows errors and warnings on each node, and the step inspector
  lists them with their fixes. Settings outside the capability contract (a
  template's tool-native keys) are listed there and can be removed.
- A refused step is logged at debug level (it is user input, not a fault).
- Messages say "scan workflow" instead of "pipeline" (log fields
  `service`/`handler=scan_workflow`, conflicts, not found, run messages).
  An unknown tool reads `tool "x" is not installed in this organization`.
  Error codes are unchanged.
