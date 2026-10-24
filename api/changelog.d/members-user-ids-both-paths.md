### Fixed: the members list applies `user_ids` without `include=user` too
- `GET /api/v1/tenants/current/members?user_ids=...` returned the whole page when `include=user` was missing; the filter now applies on both paths.
