### Security: dashboard snapshots and trends hardened

- A pentest finding without a campaign no longer counts in the new-versus-fixed and time-to-fix trends
  of a personal dashboard for people outside every campaign (it already stayed out of current counts and
  lists). Migration `003270_dashboard_facts_pentest_no_campaign` replaces the fact builder and requests
  a full rebuild of every organization's dashboard facts, which the facts maintainer runs in short
  batches.
- Only one refresh of a dashboard runs at a time: a second Refresh now answers 429 without using the
  budget, and the scheduled refresher skips a dashboard that is being refreshed.
- A Refresh now that found no read slot free gives its budget back (a computation that started and failed keeps it).
- Widget previews are limited per person (a burst of 24, then one every 2 seconds; 429 with
  `Retry-After`).
- A member's personal dashboard snapshots are deleted as soon as the membership is removed, suspended
  or offboarded (migration `003271_dashboard_snapshots_member_removal`; existing snapshots of former
  members are deleted on upgrade).
