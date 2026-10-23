### Removed: automation types that never ran

- The `schedule`, `finding_age`, `finding_updated` and `webhook` triggers, the `assign_team`, `update_priority`, `run_script`, `http_request` and `trigger_pipeline` actions and the `pagerduty` notification are no longer types. Nothing fired these triggers, and every run of these actions failed or was refused. A node that names one is refused with 400 `UNSUPPORTED_WORKFLOW_FEATURE`.
- Migration 003361 (`automations_removed_types`) switches off every automation that still holds such a node and records why (`automations.disabled_reason = uses_removed_type`, shown on `GET /api/v1/workflows/{id}`). No automation is deleted. Saving a graph of known types clears the reason, and the automation can then be switched on again. The stored headers of `http_request` nodes are dropped, because they often held credentials in plain config.
- The unused `configs/workflow-templates/auto-remediation.json` template is removed.

### Added: automation catalog

- `GET /api/v1/workflows/catalog` (`findings:workflows:read`) lists the trigger, action and notification types the engine runs, with the permission each needs and whether the caller holds it. The console builds its palette from it.
