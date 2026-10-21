### Added: typed dashboard widgets and the widget metric catalog

- A dashboard widget can now be a typed widget (`widget_type` `metric` or `note`) whose config names
  a metric from the catalog, a filter and group-by on fact dimensions, a time window, a comparison, a
  visualization and an optional target. The server validates every typed widget strictly on create,
  update and copy (unknown fields, metrics, dimensions, values and visualizations that do not fit the
  result shape are refused with 400) and stores the normalized config.
- `GET /api/v1/me/dashboards/widget-catalog` lists the metrics (open findings, priority exposure, KEV
  exposure, age bands, within SLA, open by priority over time, new vs fixed, time to fix, fix next, SLA
  at risk), their dimensions, result shapes and fitting visualizations.
- Existing dashboards are unchanged: legacy widget ids keep working. No migration.
