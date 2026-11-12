### Security: a session without an organization reaches only its own account

- An access token without a tenant (a person in no organization, or a social or SSO sign-in before an organization is chosen) is refused with `401 TENANT_REQUIRED` on every route outside an explicit account allow-list: profile, preferences, password, two-factor, sessions, sign-in methods, account deletion, creating an organization where allowed, accepting an invitation, step-up and sign-out. Previously routes mounted without the tenant chain (for example `/openapi.yaml` and `/api/v1/ws`) accepted it. A route test checks every user-plane route against the list (RFC-141).

### Added: account token and declining an invitation without the email link

- `POST /api/v1/auth/account-token` gives a person with no organization they can open an account-only access token, so they can manage their account; members get 409 and exchange for their organization as before.
- `POST /api/v1/auth/onboarding/decline` declines an invitation listed for the verified address, by its account-bound reference; audited in the inviting organization.
