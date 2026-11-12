### Changed: the run map says why a step's chunks wait

- A waiting step no longer always reads "Waiting for a sensor". When every queued chunk waits for hosts another task of the organization is scanning, it reads "Waiting for its hosts: another task is scanning them". When every one was refused by a sensor's local policy, it reads "Waiting for a sensor whose local policy allows it". Otherwise each gate's count is listed on the step card and in its panel, for running steps too.
- `GET /scan-runs/{id}/map`: node `chunks` gains `hosts_busy` and `refused` (subsets of `queued`), and a waiting node's `reason` can be `waiting_for_hosts` or `waiting_after_refusal`, besides `waiting_for_sensor`.
