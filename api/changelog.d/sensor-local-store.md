### Added: sensors report a full local store, and a waiting scan says so

- Protocol v2 feature `local_store`: the heartbeat of a sensor built on sdk-go with a local store carries the store's watermark, whether it stopped claiming new jobs and why, bytes per class, the disk level and the cleanup sweeps. It is read leniently, clamped and sanitized, and stored in `sensors.reported_local_store` (migration `sensor_local_store`, two nullable columns, no rewrite).
- `GET /api/v1/sensors` and `GET /api/v1/sensors/{id}` return it as `local_store`. A sensor that stopped claiming gets the critical health reason `stopped_claiming` with what to do. Before, a sensor that stopped claiming because its disk was low looked idle and its scans only said "Waiting for a sensor".
- The run task placement explanation names such a sensor with `stopped_claiming` instead of counting it eligible.
- The sensor response also carries `auth_kind` (`bearer` or `key_bound`).
- Display, health and explanations only: dispatch does not change.
