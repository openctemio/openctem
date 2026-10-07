### Added: API descriptions of web origins and their drift

- `POST /api/v1/assets/{id}/api-specs` uploads an OpenAPI 3, Swagger 2, Postman 2.1, HAR 1.2 or GraphQL introspection
  document for a web origin; `GET /api/v1/assets/{id}/api-specs`, `GET /api/v1/api-specs/{id}`,
  `GET /api/v1/api-specs/{id}/drift` (shadow, orphan, zombie, parameter drift) and `DELETE /api/v1/api-specs/{id}`.
- Only the declared operations (method, path, parameter names, deprecated) and the document's digest are stored
  (migration 001209); the document, its examples and captured values are not. No remote reference is fetched.
  Design: RFC-056.
