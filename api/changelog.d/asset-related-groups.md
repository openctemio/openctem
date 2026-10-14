### Added: related assets grouped by relationship

- `GET /api/v1/assets/{id}/relationships/groups` returns an asset's relationships grouped by type and direction, each group with its total and its first rows (most critical related asset first, with its status, criticality, exposure and last seen, and the edge's source and last verified time). With `type` and `direction` it pages through one group, with a name search.
- Related assets outside the caller's data scope are never returned; only their number is (`hidden_count`), and a search never narrows it.
