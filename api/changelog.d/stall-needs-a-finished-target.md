### Fixed: a batch tool is no longer re-queued as stalled before it finishes a target

A scan command is called stalled only after it has finished at least one target and then stopped making progress. Tools that write their output only when they exit (httpx, naabu) report no finished target until the end, so they were re-queued at every stall window and the command was exhausted after three attempts (`COMMAND_EXHAUSTED`). They are now bounded by the task's overrun limit only.
