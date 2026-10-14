### Changed: a task waiting for its hosts says so, and which task holds them

- The "Why waiting?" panel of a queued task that waits while another task of the organization scans its hosts now reads, for example, "Waiting: 10 of its 10 hosts are being scanned by httpx (step http). It starts when those hosts are free." It replaces "Sensors that can take it: 1 (0 busy). It should start shortly." and links the run that holds the hosts.
- The answer shows host counts only, never host names. A holding task's run and step are named only when the caller can read that run, and another organization's tasks are never counted.
- The run's task list marks such a task "Waiting for its hosts".
- A sensor that hands a task back because its own per-host limit holds one of the hosts is stored as the code `hosts_busy`, and shown as such ("its sensor is still scanning one of its hosts").
- API: `GET /scan-runs/{id}/tasks/{task_id}/placement` adds `host_wait` (`hosts_held`, `hosts_total`, `holders[]`) and the reason `sensor_hosts_busy`. Run tasks add `waiting_on_hosts`.
