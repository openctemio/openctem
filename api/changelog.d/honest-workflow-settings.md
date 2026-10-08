### Fixed: a scan workflow's settings do what they say

- The workflow **timeout** now applies. A run started without a scan, or from
  a scan that has no timeout of its own, ends at the workflow's
  `timeout_seconds`. A scan's own timeout still wins, and 24 hours remains
  the ceiling.
- Editing a workflow in the form no longer rewrites its steps. The form
  showed a few fields of each step, and saving replaced the rest (preferred
  tools, conditions, step configuration). Steps of an existing workflow are
  edited in the visual builder only.

### Removed: workflow settings that never did anything

- Workflow `triggers` (manual, schedule, webhook, on asset discovery) were
  stored and never acted on. Schedules belong to scans, and events belong to
  Automations. `notify_on_complete`, `notify_on_failure`,
  `notification_channels` and `retry_failed_steps` were never applied either.
  All five are gone from the API, the domain and the console.
- The per-step "Retries" field is no longer offered in the builder: step
  retries are not applied yet.
