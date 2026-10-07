### Changed: stored discovered-URL assets become web endpoints

- Migration 001274 turns every `discovered_url` asset into a GET endpoint under its origin (`http_service`, created
  when missing; origin named `scheme://host[:port]`, default port dropped), keeping query parameter names only, moves
  their findings and exposure events to the origin and deletes the URL assets. Design: RFC-056.
- Upgrade note: the down migration does not recreate the URL assets; the endpoints keep the inventory.
