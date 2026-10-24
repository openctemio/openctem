### Security: automation runs and personal dashboards follow the reader's permissions

- A run that lists several discovered assets, and a run for a finished scan, no longer show a reader limited
  to their data scope any asset outside it: the asset list is cut to the assets the reader may see and step
  inputs, outputs and delivery payloads of such a run are removed. Readers who may see every listed asset get
  the run unchanged. Applies to run detail, the run list and deliveries.
- `GET /api/v1/me/dashboards/{id}/data`, `POST /api/v1/me/dashboards/{id}/refresh` and
  `POST /api/v1/me/dashboards/widget-preview` now need `dashboard:read`, and a widget needs the permission of
  what it counts (`findings:read` for finding metrics, `assets:read` for asset metrics). A widget the role may not
  read is returned as unsupported with reason `forbidden` and no figure.
- CI: a push to `develop` that adds a migration numbered at or below develop's highest before the push fails the
  migration version check, as the merge queue already does.
