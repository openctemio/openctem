### Security: step-up on secret-store and module writes

- Creating, updating, rotating and deleting a stored secret (`/api/v1/secret-store`) and turning modules on or off (`PATCH /api/v1/tenants/{tenant}/settings/modules`, `POST .../settings/modules/reset`, `POST .../settings/modules/presets/{presetId}/apply`) now need a recent re-authentication (step-up), like the IP allowlist and the other security settings already did. The web console asks for it in place. Validate and preview stay without step-up.

### Security: SCIM tokens expire and can be rotated

- A new SCIM token needs `expires_in_days` (1 to 365); an expired token is refused with 401. `POST /api/v1/scim-tokens/{id}/rotate` (owner, step-up, audited) mints a replacement, shown once, and the old token keeps working for 24 hours so the identity provider can switch. The token list shows each token's expiry and an `expired` status. Migration 003300 adds `scim_tokens.expires_at`.
- **Upgrade note:** existing SCIM tokens expire 90 days after the migration runs. Rotate them in Settings > Directory sync (SCIM) before then and paste the new token into the identity provider. A client that creates tokens through the API must now send `expires_in_days`.
