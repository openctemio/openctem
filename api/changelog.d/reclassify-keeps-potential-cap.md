### Fixed: the priority recompute no longer undoes the P2 cap on potential version matches

- A version match below 80 percent confidence (for example a banner match) that is not in the known exploited list and not confirmed by a scan is capped at P2 when the matcher creates it. The priority recompute ran afterwards without that rule and moved such findings back to P1, so they got the P1 SLA and showed as overdue. The recompute now applies the same cap (one shared function), so these findings stay at P2.
- Findings already moved to P1 come back to P2 on their next recompute (the daily reconcile of every open finding); no manual data change is needed. A priority set by hand is never capped.
- SLA deadlines follow the existing rule: a deadline is never moved later by a recompute, so a finding that already has a P1 deadline keeps it (an extension stays an explicit decision). New findings get the P2 deadline.
