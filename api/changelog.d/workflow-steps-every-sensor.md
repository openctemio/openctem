### Changed: a workflow step runs on every eligible sensor

- A workflow step is no longer pinned to one sensor when it is queued. Its commands go to the run's zone, the platform queue or the organization's own sensors, and any sensor there that has the tool and whose grant admits the job may take them.
- A large step is cut into chunks, so several sensors share it. The chunk size comes from the step's capability (for example 200 targets for an HTTP probe or DNS resolution, 50 for a port scan, 25 for vulnerability templates). The step finishes with its last chunk: it fails only when every chunk failed, and ends partial when some did. When a sensor stops renewing its lease, its chunk goes back to the pool for another sensor.
- A workflow scan with several targets is no longer warned that only its first target is scanned.
