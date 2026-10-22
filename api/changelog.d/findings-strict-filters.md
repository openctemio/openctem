### Behaviour change: Unknown filters on the findings list are rejected

- `GET /findings`, `GET /findings/stats`, `GET /findings/groups` and `GET /findings/export` answer an
  unknown query param with `400 INVALID_FILTER`; `details[].param` names it and `details[].reason` is
  `"unknown filter"`. They used to ignore it with a `Warning: 299` header and return every finding, so a
  typo silently widened the list, its counts and exports.
- Old param names (`severities`, `statuses`, `search`, ...) still work with `Deprecation` and `Sunset`
  headers. `GET /meta/filters/findings` lists every accepted name.
- Integrations that send extra params to these endpoints must drop them.
- `assigned_to_me` accepts only `true` (assigned to or owned by me) and `false` (no filter); any other
  value is `400 INVALID_FILTER` instead of silently returning every finding.
