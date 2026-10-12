### Added: web endpoints API

- `GET /api/v1/web-endpoints` (list query contract), `/web-endpoints/stats`, `/web-endpoints/{id}`,
  `/web-endpoints/{id}/parameters`, `PATCH /web-endpoints/{id}` (state active or ignored, labels; audit-logged)
  and `GET /api/v1/assets/{id}/web-endpoints`.
- An endpoint is visible exactly when its origin asset is: the caller's data scope is part of every list and count,
  and an out-of-scope or other-tenant id answers 404. Design: RFC-056.
