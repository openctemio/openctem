### Behaviour change: single sign-on is no longer a deniable feature; a count limit caps connections

- The named features `sso.connections` and `sso.enforcement` are removed. Signing in through SSO, configuring a connection and requiring SSO are security controls and are never withheld by a plan or an operator deny.
- New limit key `sso_connections` (SAML configuration plus OIDC identity providers). At the limit only creating another connection is refused; changing or deleting a connection, signing in and requiring SSO keep working. Without a limit source (self-managed Community) it is unlimited. The limit shows in Settings > Limits.
- The hourly sweep that switched SSO enforcement off after a downgrade is removed, together with its controller: enforcement stays on after a limit change.
- A control plane that still sends `sso.connections` or `sso.enforcement` in `denied_features` is refused as an unknown feature; send `sso_connections` in `limits` instead.
