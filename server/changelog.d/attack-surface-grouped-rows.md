### Fixed: attack surface lists fold the same issue into one row

- Attack surface › Overview, Fix first: the same issue on many assets (for example "Redis reachable from the internet without authentication" on ten addresses) is one row with the latest asset and a "+9 more" link to the exposure list narrowed to that issue, instead of ten rows that differ only by address. `GET /api/v1/easm/summary` `top_risks` rows now carry `count` and `assets`.
- Attack surface › Changes: the changes of one kind on one asset (a lookalike of one domain registered hundreds of times) are one row with "Show all N changes", which opens every one of them over the page, newest first, paged. The groups page like the changes did. `GET /api/v1/easm/changes` takes `grouped=true` (rows in `groups`) and `group_kind`, `group_detail`, `group_asset` (one group's changes).
- Attack surface › Posture, Fix plan: one category heading per run of steps, the score and grade only on the step that changes them (no more "53 F" on every row), each row keeping its asset and issue count; a long plan shows its first 8 steps and the rest with "Show more".
- Docs: server/docs/rfcs/RFC-080-attack-surface-changes-and-digest.md
