### Security: a cached signing key stops verifying after 6 hours without a refresh

- When an OIDC provider cannot be reached (single sign-on providers and the CI providers' token issuers), keys fetched earlier keep verifying tokens for at most 6 hours, down from 24. A key the provider has withdrawn is no longer accepted for a day while the platform cannot refetch.
- An outage longer than 6 hours now stops sign-ins through that provider, and CI exchanges against it, until the provider is reachable again.
