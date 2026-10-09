### Changed: automations are named automations in the database and the Go code (migration 001528)

- Migration 001528 renames the automation tables: `workflows` to `automations`, `workflow_nodes` to `automation_nodes`, `workflow_edges` to `automation_edges`, `workflow_runs` to `automation_runs` and `workflow_node_runs` to `automation_run_steps`; the `workflow_id` / `workflow_run_id` columns to `automation_id` / `automation_run_id`; and every index, constraint, trigger and RLS policy named after them. Rows and ids are unchanged. There are no compatibility views.
- The Go packages `internal/app/workflow` and `pkg/domain/workflow` are now `internal/app/automation` and `pkg/domain/automation`; the postgres repositories are `Automation*Repository`.
- The HTTP API (`/api/v1/workflows`), the permission ids and the module id are unchanged by this entry.
- **Upgrade note:** one step. Stop the old api, run the migration, start the new api: an api from before this release cannot read the renamed tables. Custom SQL or BI queries on the old table names must use the new ones. Run the migration explicitly; `air` does not run migrations.
