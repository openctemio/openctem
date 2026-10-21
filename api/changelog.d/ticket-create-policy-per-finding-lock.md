### Fixed: the automatic ticket path and the hold release job can no longer file the same finding twice
- Creating an issue for a finding now takes a per-finding lock shared by the workflow action, a person's Create ticket and the hold release job; a second create waits and reuses the first issue.
- The hold release job gets a 10-minute run budget (a batch of tracker calls outlasts the 2-minute default) and a covering index for its due-holds query.
