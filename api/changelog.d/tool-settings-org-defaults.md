### Added: organization tool defaults, with per-sensor overrides

- Owners and administrators can set, per tool, the values that every one of the organization's own sensors runs the tool with: `GET /api/v1/sensors/tool-defaults`, plus `PUT` and `DELETE /api/v1/sensors/tool-defaults/{tool}`. The routes use `sensors:read` and `sensors:write`. The values are validated against every settings schema that the organization's sensors report for the tool, and every change is audited.
- A sensor's own tool settings now override the organization's defaults key by key, in either direction. A scan, a workflow step or a job can still only lower rate, concurrency and retries.
- Scan jobs carry the defaults that the claiming sensor inherits as `settings_layers.tenant` inside the signed payload. This layer leaves out the keys that the sensor overrides, and it is never sent to shared platform sensors. If the defaults no longer validate against a sensor's schema, that sensor's jobs of the tool fail with `TOOL_SETTINGS_INVALID`.
- The sensor tool settings response adds `organization_values` and `organization_problems`. The effective view and the preview add the source `tenant` and a `chain` of every layer that sets a key.
- Migration `002136_tenant_tool_settings` adds a new, empty table.

### Security: changing an Impact tool option needs a recent re-authentication

- Setting an Impact (T1) tool option to a new value, in either the organization defaults or a sensor's settings, now asks for step-up re-authentication (`403 STEP_UP_REQUIRED`). Organization changes to an Impact option are audited at high severity.
