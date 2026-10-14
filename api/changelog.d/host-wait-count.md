### Changed: a task waiting for its hosts says how many, held by what, and what can start

- In a run's task list, a queued task waiting for its hosts now reads in full, for example "Waiting for 2 of its hosts, held by nuclei (step templates, run 1a2b3c4d); 21 of its 23 targets are on free hosts", instead of a cut-off generic sentence. The holder's run and step are named only when you can read that run. A host is never named.
- The task list (`GET /scan-runs/{id}`, `GET /scan-runs/{id}/tasks`) gives `host_wait` on such tasks (at most 25 per page). `host_wait` in the list and in the task placement answer gains `targets` and `can_start`.
