### Removed: pre-sensor AGENT_* environment variable names

- The API no longer reads the ten pre-sensor names (`AGENT_CONFIG_TEMPLATES_DIR`, `AGENT_PUBLIC_API_URL`, `AGENT_KEY_TTL`, `AGENT_LB_*`) or the old template directory `configs/agent-templates`.
- Startup now **refuses to run** while one of the old names is set, and the error names its `SENSOR_*` replacement. Ignoring them silently could, for example, turn short-lived sensor keys back into non-expiring ones.
- The Helm chart stops mapping `AGENT_*` values to `SENSOR_*` in the same release (helm-charts PR, merged first or together).
- **Upgrade note (one step):** rename any `AGENT_*` variable in your `.env`, compose file or chart values to its `SENSOR_*` name, and move custom templates from `configs/agent-templates` to `configs/sensor-templates`, before upgrading.
