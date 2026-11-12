### Added: how we found this, for findings and assets

- `GET /api/v1/findings/{id}/story` (`findings:read`) and `GET /api/v1/assets/{id}/story` (`assets:read`) return a short ordered chain from records already stored: the scope entry in effect that covers the subject, its discovery chain, the scan runs that derived, scanned or reported it, the sources that reported it and the finding. No migration.
- A step the caller may not see (an ancestor outside their data scope, the asset of a finding assigned to them outside their scope, a run without `scans:read`) is returned as hidden and counted, never named; scope entries need `attack_surface:scope:read`, sensors `sensors:read`.
