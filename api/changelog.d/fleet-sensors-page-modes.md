### Changed: the Sensors page lists CI pipelines (Mode: All, Daemon, Runner)

- The Sensors page switches by **Mode**: All, Daemon (sensor rows, heartbeat, can be offline) and Runner (CI pipelines: one per workflow file of each repository, fresh or stale against its own cadence, never offline). The role filter (scanner, collector) applies to both. Header counts per mode.
- Runner mode shows each pipeline with its provider, repository, workflow, status, last run, default-branch gate and runner version, and a drawer with its runs (paged), branches and gate trend. Archived, revoked and never-run pipelines are hidden behind **Show inactive**; nothing is deleted.
- The CI runners page is folded in: `/ci-runners` opens the Sensors page in runner mode and `/ci-runners/{run id}` (the link in a gate verdict) opens that run. The run-style facet of the daemon list is now **Run style** (`?exec=`); old `?mode=ci` links keep working.
