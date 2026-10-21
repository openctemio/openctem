### Security: a service account's key list is for owners and administrators only

- `GET /api/v1/service-accounts/{id}/api-keys` now answers 403 to anyone who is not an owner or administrator. It used to answer to every member and viewer, who could read the prefixes, scopes, creators and last-used IPs of the organization's integration keys (the key lists are admin-only by decision, 2026-10-02).
- The last-used IP of a key is no longer returned to non-administrators on any API key route. The Keys button on the service accounts page is shown to administrators only.
