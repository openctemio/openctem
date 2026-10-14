### Added: an asset's coverage on its page

- The asset page and the asset detail sheet gain a Coverage section (from
  `GET /api/v1/assets/{id}/coverage`): per capability the asset's type
  needs, its state (covered, due, running, failed, blocked, paused, not
  applicable), the reason it was skipped, when it last ran and when it is due
  next, the last error, and whether it is a coverage gap. English and
  Vietnamese.
