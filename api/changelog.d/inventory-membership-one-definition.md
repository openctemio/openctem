### Changed: one inventory definition; review items say what covers them

- Dashboard asset totals and the EASM surface, new-asset and exposed-service
  counts now count only inventory members (confirmed or unrecorded,
  `dependency`, `monitor_only`), like the Assets list and the attack-surface
  stats (RFC-054 §4.4). Names waiting for review are no longer counted as
  surface.
- Attack-surface "recent changes" items carry `asset_id`,
  `attribution_state` and `in_inventory`, so a discovered name shows as
  "Added · needs review" instead of "Added".
- The review queue (`GET /api/v1/easm/candidates`) filters by `reason` and
  says per item which scope target, seed or verified domain covers it
  (`covered_by`); the EASM summary adds `review_by_reason`.
- `GET /api/v1/assets/{id}/attribution` adds `scope_status` (`in_scope`,
  `out_of_scope`, `internal`, `not_applicable`), `covered_by` and
  `blocked_code`.
