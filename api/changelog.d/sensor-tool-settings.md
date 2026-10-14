### Added: per-sensor tool settings, validated and delivered inside the signed job

- Owners and administrators configure each tool of one of their sensors from
  the sensor drawer's new "Tool settings" tab: a form generated from the
  settings schema the tool's descriptor declares in the sensor's manifest
  (common options first, bounds, defaults, safety tags, effective values).
- `GET /api/v1/sensors/{id}/tool-settings`, `GET .../{tool}/effective`
  (`sensors:read`), `PUT` and `DELETE .../{tool}` (`sensors:write`). Values are
  validated with the CTIS settings contract (`ctis/settings`); non-default
  values of dangerous (T2) options are refused for now. Changes are audited
  as `sensor.updated` with a per-key diff; sensitive values are redacted.
- A sensor's settings for a tool travel in each scan job of that tool as
  `settings_layers.sensor`, covered by the job signature. Settings that no
  longer validate after a sensor upgrade fail the job with
  `TOOL_SETTINGS_INVALID`; save or reset them to clear it.
- Migration `002114_sensor_tool_settings` adds the `sensor_tool_settings`
  table (new and empty; no upgrade step).
