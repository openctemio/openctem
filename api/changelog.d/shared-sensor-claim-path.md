### Security: shared sensors claim shared jobs through their own claim path

- A shared sensor (scope `instance`) now claims shared jobs of every organization on `GET /api/v2/sensor/commands` (claim-N only; a listing poll answers 403 `scope-denied`), in fair-share order across organizations, within each organization's `platform_scans_concurrent` limit read from the entitlement service (an organization at its limit waits), and only when it reports the isolation capability `shared.isolation@1` and accepts unzoned jobs (`sensors.accepts_unzoned_jobs`, default true). A job naming `preferred_region` goes only to shared sensors of that region. Shared jobs share the organization's host keys and locks with its own sensors (RFC-100 §8).
- The shared sensor access policy is applied again at claim time: an organization that lost access or opted out keeps its queued shared jobs waiting.
- Each organization's candidates pass the same gates as an organization sensor's claim (grant, local policy, scope re-check, scan windows, program rules, tool settings); every claim is signed for the shared sensor in the command's organization.
- Start, complete, fail, release, logs and heartbeat lease renewal work for a shared sensor only on the shared jobs it holds, in the command's organization; complete, fail and logs require the lease epoch. An organization sensor never receives a shared job and a shared sensor never receives anything else.
- The lease, stall and stuck-job reapers now handle shared jobs; a shared job expires 60 minutes after it was queued or last went back to the queue.
- The access gate is unchanged: no organization can queue shared jobs yet.

### Removed: `get_next_platform_job` and `commands.platform_sensor_id`

- The unused queue function `get_next_platform_job`, its Go wrapper and the column `commands.platform_sensor_id` (set only by that function) are removed; the holder of a shared job is `commands.sensor_id` (migration `002650_shared_claim`).
- **Upgrade note:** the migration drops a column the previous API version reads. Stop the API during the deploy, run the migrations, then start the new API.
