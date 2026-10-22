### Security: service-account keys follow their minter's access and the full-data ceiling holds for existing roles
- Demoting an administrator now revokes the service-account keys they minted in the same transaction as the role change; if the revoke fails the demotion is refused instead of leaving the keys live.
- Suspending a member, and removing a custom role that gave a member `service_accounts:manage`, revoke the service-account keys they minted too.
- A role held by a service account (directly or through a team) can no longer be switched to full data access; the roles API and a new database trigger both refuse it.
