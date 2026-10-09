### Added: service accounts for integrations

- `GET/POST /api/v1/service-accounts`, `DELETE /api/v1/service-accounts/{id}`
  (`team:members:read` / `team:members:write`): an organization-owned identity
  for an integration (a SIEM export, a ticketing bridge). It starts with no
  role, gets custom roles and teams like a member, and acts only through API
  keys minted for it, which carry at most what it holds.
- It never signs in (no password or federated identity, enforced by the
  database), belongs to one organization only, and can never be an owner or
  administrator or hold full data access (database triggers and the role grant
  guard). Deleting it removes its roles, team memberships and keys at once
  (migration 001461).
