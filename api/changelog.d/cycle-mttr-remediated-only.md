### Fixed: CTEM cycle MTTR counts only real fixes, and an empty cycle has no MTTR

- Cycle metrics `mttr_hours`, `findings_resolved`, `validation_coverage`, `p0_resolved` and `p1_resolved` now count only remediated findings; false positives, accepted risks and obsolete closures no longer count as fixes. MTTR starts at first detection.
- A cycle that remediated nothing has no `mttr_hours` or `validation_coverage` value (null in the trend series) instead of 0, so a charter criterion such as "MTTR < 72 h" reads not measurable rather than met, and the maturity score excludes MTTR trend and validation coverage for that cycle. Values stored for earlier cycles are unchanged. No migration.
