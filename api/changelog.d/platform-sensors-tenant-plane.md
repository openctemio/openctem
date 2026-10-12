### Security: platform sensors are invisible and unmanageable on the tenant plane

- Every tenant route on one sensor (`/api/v1/sensors/{id}...`: read, rename, activate, deactivate, revoke, delete, regenerate key, signing keys, grant, content refresh, activity, manifests, heartbeat history, config report) answers 404 for a shared platform sensor, also to the organization whose id its row carries. Lists, counts, tool and capability availability, grant summaries and command pinning leave platform sensors out. Before, that organization could read and change them.
- A platform job's command, run task and run stage never name or identify the platform sensor (`platform: true` instead), and the sensor's own private addresses and host paths are masked as `[platform]` in its logs, error message and result.
- A platform sensor's attribution evidence uses the source `sensor:platform` and no sensor id.

### Removed: GET /api/v1/platform/stats

- Replaced by `GET /api/v1/platform/scanning` (sensors:read or scans:read): whether the organization may use platform scanning, each region's state, the tools it runs and the organization's own platform jobs. It shows no node count, capacity or other organization's load. The web `/sensors/platform` page is removed; the Sensors page shows a Platform scanning card when the organization may use it, and `is_platform_sensor` is gone from the sensor response.
