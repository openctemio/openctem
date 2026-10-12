### Security: organizations decide whether personal email accounts may join, and may name SSO exceptions

- **Personal accounts:** `PATCH /tenants/{tenant}/settings/security` takes `personal_accounts`.
  - `allowed`: the value for existing organizations.
  - `allowed_with_mfa`: a token needs a proven second factor. This is the default for new organizations.
  - `blocked`: personal addresses cannot be invited, cannot accept an invitation, and get no token.
- **SSO exceptions:** the same call takes `sso_exceptions`, the named members who may sign in without SSO while it is enforced.
  - Each exception has a reason and ends within 90 days.
  - A second factor is required.
  - It is honoured at token mint and on every request.
- **Look-alike warning:** creating an invitation returns `lookalike_of` when the address reaches the same mailbox as an existing member's (Gmail dots, `+tags`). It is a warning only.
