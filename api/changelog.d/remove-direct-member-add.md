### Removed: adding an existing account to an organization by user id

- `POST /api/v1/tenants/{tenant}/members` is gone. It let an organization administrator add any existing account without that person's consent. An invitation, accepted by the person it is addressed to, is now the only way an existing account joins an organization. Listing members on the same path is unchanged.
- SCIM provisioning and the platform administrator's first-owner bootstrap keep their own paths.
- **Upgrade note:** API clients that called this route must send an invitation (`POST /api/v1/tenants/{tenant}/invitations`) instead.
