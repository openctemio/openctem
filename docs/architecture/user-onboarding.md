# User onboarding and organization access policy

How people get an account and into an organization, and the two organization
access policies (allowed email domains, IP allowlist). Design and rationale:
[RFC-025](../rfcs/RFC-025-user-onboarding.md).

## Ways in

| Way | Endpoint(s) | Gate |
|-----|-------------|------|
| Organization admin creates the user | `POST /api/v1/tenants/{tenant}/users` | owner/admin of the organization |
| New set-password link for a pending account | `POST /api/v1/tenants/{tenant}/users/{userId}/setup-link` | owner/admin; account unused and in this organization only |
| Platform admin creates the user | `POST /api/v1/admin/tenants/{tenantId}/users` | console session, ops_admin+ (audited) |
| Platform admin creates an organization with a new owner | `POST /api/v1/admin/tenants` (`owner_email` without an account) | console session, ops_admin+ (audited) |
| Invitation | `POST /api/v1/tenants/{tenant}/invitations`, then register with `invitation_token` (if no account) and `POST /api/v1/invitations/{token}/accept` | owner/admin to invite; the token + matching email to accept |
| Organization SSO (OIDC/SAML JIT) | `/api/v1/auth/sso/*`, `/api/v1/auth/saml/{org}/*` | provider active + auto-provision + DNS-verified domain + allowed domains |
| Self-registration | `POST /api/v1/auth/register` | `AUTH_ALLOW_REGISTRATION=true` only (default false) |

### Administrator-created accounts

Request: `{"email": "...", "name": "...", "role_ids": ["<rbac role id>", ...]}`.
Response (201):

```json
{
  "user": {"id": "...", "email": "...", "name": "..."},
  "membership_id": "...",
  "role": "viewer",
  "email_sent": false,
  "setup_token": "<only when not emailed>",
  "setup_expires_at": "2026-10-02T10:00:00Z"
}
```

The user opens `<UI>/set-password?token=<setup_token>` and chooses a password
(`POST /api/v1/auth/reset-password`). The link is single-use and expires after
24 hours; an administrator can issue a new one while the account is unused.
Errors: 409 when the email already has an account (invite instead), 400 when
the domain is not allowed, 403 when granting roles the caller does not hold.

### Membership role from RBAC roles

`tenant_members.role` is copied into `user_roles` by a database trigger, so it
must never grant more than the roles given. It is derived from the granted
roles: `member` when they include the system member or admin role, otherwise
`viewer`. After the membership is created the granted roles replace the user's
role set exactly. The same applies to invitations (including ones created
before this rule).

## Organization access policy (Settings → Organization → Security, owner only)

### Allowed email domains (`security.allowed_domains`)

Empty = no restriction. Otherwise the email's domain (after the last `@`,
case-insensitive, exact — `corp.com` does not admit `eu.corp.com`) must be in
the list for: sending and accepting invitations, registering with an
invitation, administrator-created users, adding an existing user, SCIM
provisioning, and SSO just-in-time provisioning. Existing members are not
removed when the list changes.

### IP allowlist (`security.ip_whitelist`)

Empty = no restriction. Otherwise every request made with a user's access token
for this organization must come from a listed IP or CIDR, or it gets
`403 {"code":"IP_NOT_ALLOWED"}`. Applies to the organization in the URL
(`/api/v1/tenants/{tenant}/...`) or, elsewhere, the organization the token is
for. Not applied to: sensor/agent and tenant API keys, the platform admin
console, public routes (login, token exchange), and the platform administrator.
Changes take effect within 30 seconds on every API instance (immediately on the
one that saved them).

**Lockout guard.** Saving a non-empty list that does not contain your current IP
is refused with 400 `IP allowlist must include your current IP address (<ip>)`.
`GET /tenants/{tenant}/settings` returns the IP the server sees as
`security.current_ip`.

**Client IP.** The API uses the TCP peer, and honors `X-Real-IP` /
`X-Forwarded-For` only when the peer is in `SERVER_TRUSTED_PROXIES`. When users
reach the API through the UI's Next.js proxy, the peer is the UI container, so:

1. put a reverse proxy in front of the UI that **overwrites** `X-Real-IP` and
   `X-Forwarded-For` with the real client address;
2. set `TRUST_PROXY_HEADERS=true` on the UI so its proxy forwards them;
3. set `SERVER_TRUSTED_PROXIES` on the API to the UI's address/network.

Without that, `current_ip` shows the UI container's address and the allowlist
cannot tell users apart. Never set `TRUST_PROXY_HEADERS=true` when browsers
reach the UI directly: they could then claim any IP.

**Recovery** (everyone locked out, e.g. the office IP changed): clear the list
in the database, then wait 30 seconds or restart the API:

```sql
UPDATE tenants
   SET settings = jsonb_set(settings, '{security,ip_whitelist}', '[]'::jsonb)
 WHERE slug = '<org-slug>';
```

## Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `AUTH_ALLOW_REGISTRATION` | `false` | Open self-registration. Invited people can register either way. |
| `TENANT_CREATION_MODE` | `self_service` | `admin_only`: only the platform administrator creates organizations. |
| `SSO_ENTRA_DEFAULT_ROLE` | `viewer` | JIT role for the env Entra fallback. |
| `SMTP_*`, `SMTP_BASE_URL` | — | When set, set-password links are emailed (`<SMTP_BASE_URL>/set-password?token=`). |
| `SERVER_TRUSTED_PROXIES` | empty | Peers whose forwarding headers are trusted (IP allowlist, rate limits, audit). |

## Code map

| Piece | Where |
|-------|-------|
| Account provisioning service | `internal/app/tenant/user_provisioning.go` |
| Membership role derivation, exact role grant | `internal/app/accesscontrol/membership_role.go` |
| Domain / IP policy | `pkg/domain/tenant/security_policy.go` |
| IP allowlist middleware | `internal/infra/http/middleware/ip_allowlist.go` (wired in `routes/routes.go`, `routes/tenant.go`) |
| Registration gate | `AuthService.Register` / `pendingInvitationFor` (`internal/app/auth/service.go`) |
| SSO admission | `SSOService.jitProvisioningAllowed` (`internal/app/auth/sso.go`) |
| Set-password email | `EmailService.SendAccountSetupEmail`, template `account_setup` |
