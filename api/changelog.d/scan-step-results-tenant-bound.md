### Security: a command settles only its own organization's scan steps

- A command result settles the scan run step its payload names. The run is now loaded for the command's tenant, so a command of one organization can no longer complete, fail or advance a step of another organization's run, whatever run id its payload carries. Expired and exhausted commands are bound the same way.
- `POST /api/v1/commands` refuses a payload that sets `scan_run_id`, `scan_run_step_id` or `step_key` (400): only the platform sets them when it plans a run.

### Security: approval requests mask scanner config secrets for readers

- The scan approvals inbox masks credential-looking `scanner_config` values in a request's definition and in its before/after changes for callers without `scans:write`, as the scan read already does.

### Fixed: editing a scan checks its scanner config like creating one

- An edit that changes `scanner_config`, the tags or the cron expression passes the same checks as a new scan. A config sent back unchanged is not checked again, so older scans stay editable.
