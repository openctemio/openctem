### Behaviour change: a finding closed as mitigated is not reopened by detection

- A scan that sees again a finding resolved as `mitigated` (a compensating control) leaves it resolved: no reopen, no regression flag, no restarted deadline, no new notification. Validation re-checks the control.
- Re-detection now reopens a resolved finding by its status and closure reason only. A resolve note that happens to read "duplicate", "suppressed" or similar no longer blocks a real regression.
