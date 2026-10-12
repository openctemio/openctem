### Changed: sensor install snippets and fix-it snippets use the SENSOR_ names

- Install commands, configuration templates and the configuration checklist's fix snippets set `SENSOR_API_URL`, `SENSOR_API_KEY`, `SENSOR_REGION` and `SENSOR_KEY_AUTORENEW` (the sensor release that ships with this version refuses the old `API_URL`, `API_KEY`, `REGION`, `PLATFORM_KEY_AUTORENEW`).
- **Upgrade note:** rename those variables on existing sensor hosts when upgrading the sensor.
