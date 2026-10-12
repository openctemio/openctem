### Added: a pentest finding's retest history shows the testers' retests

- `GET /api/v1/findings/{id}/retests` now lists, for a pentest finding, the
  retests testers recorded by hand (`kind: manual`, with `manual_result`,
  `notes` and `tested_by`) next to automated retests (`kind: automated`),
  newest first: one history per finding. The finding page shows them.
- For a pentest finding the history follows the campaign's rule: only
  campaign members and admins see it; anyone else gets 404, as on every other
  pentest surface.
