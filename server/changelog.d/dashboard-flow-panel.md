### Behaviour change: existing dashboards get the exposure flow panel once

- Every dashboard that existed before this release is offered the exposure flow panel once, at the top of its layout, the first time someone who may edit it opens it. A toast offers Undo; a removed panel is never added again. Empty dashboards and dashboards that already show the flow are left alone; new dashboards are never changed.
- New routes `POST /me/dashboards/{id}/flow-panels`, `DELETE /me/dashboards/{id}/flow-panels/{widget_id}` and the same under `/organization/dashboards/{id}` (needs `dashboards:org:manage`). Dashboards carry `flow_panel_at`. Adding and undoing are audited (`dashboard.flow_panel_added`, `dashboard.flow_panel_undone`).
- Migration adds the nullable column `user_dashboards.flow_panel_at` (no rewrite, no downtime).
