### Removed: `GET /api/v1/fleet`, the list of sensors and CI pipelines in one response

- The console no longer shows CI pipelines on the Sensors page, so the union read model has no caller. Use `GET /api/v1/sensors` for sensors and `GET /api/v1/ci/pipelines` for CI pipelines; both keep their filters, counts and permissions.
- The notification event category that holds `sensor.offline` and the CI pipeline signals is now labelled "Sensors and CI pipelines" (its id, `sensor`, is unchanged).
- **Upgrade note:** a script that called `GET /api/v1/fleet` must call the two lists instead.
