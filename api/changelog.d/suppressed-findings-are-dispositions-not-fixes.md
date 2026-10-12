### Changed: suppressed findings are dispositions, not fixes

- **A suppression rule marks a finding `false_positive` or `accepted`,
  never `resolved`** (research 18 F7, owner decision O9). A false-positive
  rule gives `false_positive`; accepted-risk and won't-fix rules give
  `accepted`. The resolution stays `suppressed` and `finding_suppressions`
  names the rule. Fix rate and MTTR therefore count real fixes only.
- Migration 000751 moves existing `resolved` / `suppressed` rows to the
  disposition of their recorded rule (same tenant), only when that rule is
  certain; rows with no recorded rule or conflicting rules stay as they are.
  The relabel is not counted as a regression.
