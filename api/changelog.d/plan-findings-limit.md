### Added: a findings plan limit

- New plan limit `findings` (Console > System > Plans, and per organization
  in Console > Organizations > Plan). Unlimited on every plan by default; an
  operator sets it to stop one organization's sensors from growing the shared
  database without bound.
- Ingest admits new findings up to the limit and refuses each one over it
  with a per-item error; assets, the other findings and re-sightings of
  existing findings are still stored. Manual create and import answer 403
  `PLAN_LIMIT`.
- Findings are counted only while a findings limit applies, and a check of
  any unlimited key no longer counts usage, so organizations without the
  limit pay nothing for it. No migration.
