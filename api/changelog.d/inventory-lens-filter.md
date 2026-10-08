### Added: filter the asset inventory by lens and by minimum risk

- `GET /api/v1/assets` and `GET /api/v1/assets/stats` take
  `lenses=<lens>,...`, matching the stored lens of each asset, so an alias
  stored under another type's name (a container registry stored as storage)
  is listed with its own lens. An unknown lens is refused with 400.
- The inventory shows the lenses as pills above the list (`/assets?lens=`),
  and the stats strip has a "High risk" metric that filters to a risk score
  of 70 or more (`min_risk_score`). The inventory overview links each lens
  card to its lens, and its high-risk count to that filter.
