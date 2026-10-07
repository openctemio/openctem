### Fixed: a workflow scan whose first step cannot start fails at once with the reason

- A workflow scan run whose first step could not be queued (no tool for the capability, no compatible target, no sensor for the tool) answered 201 and stayed `running` until its deadline, up to 24 hours. The other first steps now still start, the run is re-evaluated at once, and a run in which nothing can run settles `failed` immediately.
- A failed scan run's message names the first failed step, its reason and its code (for example `Step "Port scan" failed: ... (NO_MATCHING_TOOL)`) instead of "Pipeline completed with failures".
