### Behaviour change: capabilities are one resource, /api/v1/capabilities

- `GET /api/v1/capabilities` lists the platform capabilities and the
  organization's own custom ones, with `source=platform|custom`, `category`,
  `q`, `page` and `per_page` (max 100), and `include=usage` (tool and sensor
  counts). `GET /api/v1/capabilities/{id}?include=usage` also names the tools
  and sensors. The usage needs `scans:tenant_tools:read`; without it the
  include is left out and listed in `meta.omitted_includes`. Sensor names
  need `sensors:read`.
- Custom capabilities are created, changed and deleted at `POST /api/v1/capabilities`
  and `PUT`/`DELETE /api/v1/capabilities/{id}`, with `scans:tools:write` /
  `scans:tools:delete` (owner and admin), as custom tools are. A member could
  do this before with `scans:tenant_tools:write`.
- Changing or deleting a platform capability or another organization's
  custom capability answers 404 (it answered 403). The repository update
  and delete are now scoped to the organization as well.
- **Removed:** `GET /api/v1/capabilities/all`, `GET /api/v1/capabilities/by-category/{category}`,
  `GET /api/v1/capabilities/{id}/usage-stats`, `POST /api/v1/capabilities/usage-stats`
  and `/api/v1/custom-capabilities[/{id}]`.
- **Upgrade note:** clients move to the routes above (`/all` is the list with
  `per_page=100`; `by-category` is `category=`; usage is `include=usage`).
