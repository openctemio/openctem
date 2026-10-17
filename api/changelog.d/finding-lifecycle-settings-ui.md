### Added: Settings → Findings → Finding lifecycle in the web console

- A new Findings group in Settings holds Finding lifecycle, Finding approvals and Vulnerability matching.
- Finding lifecycle manages the organization's sub-statuses (a lane per status: add, rename, colour,
  reorder, archive, reactivate) and its lifecycles: edit the draft's moves and their requirements, check
  it against the validator, publish it (a recent sign-in is asked for) and roll back to an earlier version.
- Read-only for members with `findings:read`; changing needs `findings:lifecycles:write`. Plan limits on
  sub-statuses and lifecycles are shown, and adding stops at the limit.
