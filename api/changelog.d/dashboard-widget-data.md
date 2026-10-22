### Added: dashboard widget results from the fact tables

- `GET /api/v1/me/dashboards/{id}/data` computes every widget of your own dashboard for your data scope;
  `GET /api/v1/organization/dashboards/{id}/data` computes an organization dashboard for the whole
  organization (needs `dashboards:org:view`, 404 outside the dashboard's audience);
  `POST /api/v1/me/dashboards/widget-preview` computes one widget spec for your scope.
- Results come from the dashboard fact tables, not from the findings table: open counts with the
  previous period and a sparkline, the share within SLA, time to fix (median and p90 from hour buckets),
  open findings by priority over time, new vs fixed, and the fix-next and SLA-due lists. Each result
  says when a figure is not measured and links to the findings list counted with the same filter.
- Pentest findings count only for campaign members on personal dashboards; organization dashboards
  count them, but list titles still follow the viewer's campaign membership.
- Reads are limited per user, organization and API process (429 with `Retry-After`).
