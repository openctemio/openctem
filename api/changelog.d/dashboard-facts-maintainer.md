### Added: dashboard facts are built and kept current; "Rebuild dashboard data"

- Two background controllers maintain the dashboard fact layer: `dashboard-facts` (every 30 s) processes change
  marks per organization in round-robin; `dashboard-facts-reconcile` builds every organization's facts once, runs a
  nightly reconciliation that fixes and counts drift, marks crossed age bands daily, creates the daily-fact
  partitions ahead and drops those older than 13 months.
- Owners and administrators can ask for a rebuild (`POST /api/v1/dashboard-data/rebuild`, status at
  `GET /api/v1/dashboard-data/`), as can console operations administrators for one organization
  (`/api/v1/admin/tenants/{tenantId}/dashboard-data`). One request per organization per hour (429 with
  `Retry-After`), audited as `dashboard_data.rebuild_requested`.
- New metrics `openctem_dashboard_fact_lag_seconds`, `openctem_dashboard_fact_queue_depth`,
  `openctem_dashboard_fact_queue_oldest_seconds`, `openctem_dashboard_fact_drift_rows_total`,
  `openctem_dashboard_fact_runs_total`, and alerts `DashboardFactsLagging` and `DashboardFactsDrift`.
- Migration `002963_dashboard_facts_maintainer`.
- **Upgrade note:** no action. After the upgrade the reconcile controller builds each organization's facts in
  batches of 200 assets (short transactions), most urgent first; dashboards do not read the facts yet.
