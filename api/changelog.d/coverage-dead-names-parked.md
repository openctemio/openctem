### Changed: continuous coverage parks names that do not resolve instead of failing them

- A name that does not resolve was scored as a failed or blocked DNS check and retried every few hours, and it could raise coverage gaps and failure streaks. On one installation 77% of the DNS checks never settled for this reason.
- A DNS check that finds no address now settles the name as checked with the outcome "no answer" and parks it: port scans, HTTP probes and template scans are not sent to it, and its DNS is rechecked after 1 day, 3 days, 7 days and then weekly. A parked name is never a coverage gap.
- When a parked name resolves again, its checks go through the full scope gate again, so a name taken over by someone else is refused there.
- Another check whose target the sensor could not resolve is held as "unresolvable" on the same schedule instead of failing.
