### Removed: the declared tool list on a sensor (`sensors.tools`)

- The `tools` field is gone from `POST /api/v1/sensors`, `PUT /api/v1/sensors/{id}` and the sensor response, and `capability_mismatch.tools_not_installed` is gone with it. The tools dispatch uses are in `effective.tools`; what the sensor reported is in `reported.tools`. The web console drops the tool-limit picker (Edit sensor, the install review) and the "installed but not allowed" notices.
- Migration 001149 drops `sensors.tools` and redefines the generated `effective_tools` as the reported installed tools (`COALESCE(reported_tool_names, '{}')`).
- **Upgrade note:** re-adding the stored generated column rewrites the `sensors` table under a short exclusive lock. The table holds one row per sensor, so this takes milliseconds. The old declared lists are not kept; the down migration restores an empty column.

### Behaviour change: dispatch uses every tool the sensor reports

- The declared list was set when a sensor was created and went stale (a sensor reporting nine tools still had four declared), and it narrowed dispatch, so a tool installed later never got jobs. Dispatch, the v2 result tool gate, the manifest policy echo and the generated install configs now use the installed tools the sensor reports.
- To narrow a sensor's tools, edit its grant (`sensor_grants.tools`, RFC-052). Dispatch already enforces the grant.
- A sensor that has never reported its tools gets no tool jobs and may not push results until it reports them. That was already true for dispatch; now it also holds for the result gate. Sensors from v0.9.0 report their tools on every heartbeat. Fleet health flags a connected sensor without reported tools as `no_tools`.
