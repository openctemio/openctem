### Added: a scan can set the standard params of single workflow steps

- `step_params` on a scan (create, update, read, export, import) overrides capability standard params per workflow step, or for every step of a capability (`*:vuln.templates`), without copying the workflow, so system workflows can be tuned per scan. The override applies after the workflow step and its depth overlay.
- Unknown params, tool extras, wrong values and intrusive template tags are refused when the scan is saved. The tag refusal list for workflow steps now also covers `default-login`, `bruteforce` and `brute-force`, as the sensor tier already did.
- The New and Edit scan wizard shows a Step settings section (severity, tags, excluded tags of template steps) with the workflow's value and an override switch.
- Migration 20261104165231 adds `scans.step_params` (constant default, no table rewrite).
