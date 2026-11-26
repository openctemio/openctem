### Security: SAML addresses are keyed by connection, not by the organization's name

- The SAML sign-in addresses and the SP entity ID (`/api/v1/auth/saml/<key>/{metadata,login,acs}`) were built on the organization's current slug. After a rename, another organization could take the old slug and be addressed by the first organization's identity provider. They are now keyed by the SAML connection's random id, and the organization's current slug never addresses a connection. Renaming an organization no longer changes its SAML addresses.
- Configurations that exist when you upgrade keep their current address, frozen: migration `20261126024604_saml_connection_addresses` stores each one's slug at that moment as its legacy key, and only that configuration answers on it, also after a rename. This legacy address is deprecated: each sign-in through it logs a warning. New configurations get only the connection-id address.
- The admin console shows the addresses returned by the API (`GET /api/v1/admin/tenants/{tenantId}/sso/saml/sp-metadata` now returns `entity_id`, `acs_url`, `login_url`, `connection_key` and `legacy`). They exist before the first save, which takes the same id. Deleting the configuration retires its address.
- The AuthnRequest no longer sends a RelayState.
- **Upgrade note:** nothing to change at existing identity providers. To move a legacy connection to a permanent address, delete and recreate the configuration, then upload its new metadata to the identity provider.
- Docs: server/docs/architecture/saml-sso.md
