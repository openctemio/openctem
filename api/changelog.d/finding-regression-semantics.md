### Behaviour change: a finding seen again after a fix reopens by what it was

- A finding closed as fixed that a scan reports again reopens on the same record as `new` when no one had triaged it, and as `confirmed` when someone had (it was always `confirmed` before).
- A fix a retest or a review verified that is seen again is a "verified fix regressed": the timeline and the announcement say so.
- A finding the platform closed on its own (no person, nothing verified) and a scan reports again within 7 days is "seen again": it reopens, but it is not counted as a regression, gets no new SLA clock and is not announced. Findings that flap between found and not found no longer inflate the regression count.
- A regression is now also told in the app to the finding's assignee and to its watchers who can read the finding.
- A scan that reports a duplicate again now counts as a sighting of the finding it was folded into: that finding is no longer auto-resolved while its duplicate is still reported, and it reopens if it was closed.
