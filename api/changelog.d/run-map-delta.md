### Added: the run map compares with the previous run

- Each step on the run map shows what is new and what is gone compared with
  the previous finished run of the same scan, and the map warns about a
  finished step that produced nothing (no asset and no finding).
- Opening a step lists what it produced, new ones first:
  `GET /api/v1/scan-runs/{id}/outputs?step_key=` (`scans:read`, up
  to 50 assets, only those in the viewer's data scope).
