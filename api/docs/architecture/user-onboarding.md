# User onboarding and organization access policy

How people get an account and into an organization, and the two organization
access policies (allowed email domains, IP allowlist). Design and rationale:
[RFC-025](../rfcs/RFC-025-user-onboarding.md).

## Ways in

| Way | Endpoint(s) | Gate |
|-----|-------------|------|
| Organization admin creates the user | `POST /api/v1/tenants/{tenant}/users` | owner/admin of the organization |
| New set-password link for a pending account | `POST /api/v1/tenants/{tenant}/users/{userId}/setup-link` | owner/admin; account unused and in this organization only |
| Platform admin creates the **first owner** of an organization with no owner | `POST /api/v1/admin/tenants/{tenantId}/users` | console session, ops_admin+ (audited); 409 once the organization has an owner, active or suspended — see [First owner](#first-owner-platform-administrator) |
| Platform admin recovers an organization whose owners are all suspended | `POST /api/v1/admin/tenants/{tenantId}/users` with `"recovery": true` | console session, **super_admin** (403 otherwise); link emailed only; audited as `organization.owner_recovery` and at critical severity in the organization |
| Platform admin creates an organization with a new owner | `POST /api/v1/admin/tenants` (`owner_email` without an account) | console session, ops_admin+ (audited) |
| First organization at install | `bootstrap-admin -org-name … -org-owner-email …` (CLI, same service as the console path) | database credentials; audited with actor `bootstrap-admin` |
| Invitation | `POST /api/v1/tenants/{tenant}/invitations`, then register with `invitation_token` (if no account) and `POST /api/v1/invitations/{token}/accept` | owner/admin to invite; the token + matching email to accept |
| Organization SSO (OIDC/SAML JIT) | `/api/v1/auth/sso/*`, `/api/v1/auth/saml/{org}/*` | provider active + auto-provision + DNS-verified domain + allowed domains |
| Self-registration | `POST /api/v1/auth/register` | `AUTH_ALLOW_REGISTRATION=true` only (default false) |

### First owner (platform administrator)

The platform administrator only bootstraps organizations (owner decision
2026-10-02, RFC-022 revision 5). `POST /api/v1/admin/tenants/{tenantId}/users`
with `{"email": "...", "name": "..."}` (`role` may be omitted; anything but
`owner` is a 400) creates the owner of an organization that has no owner, and
answers 409 otherwise, also when the only owner is **suspended**: from then on
the owner and its administrators invite or create users. The account has no password until the owner sets one
through the one-time link. The link is emailed when the organization can send
email (tenant or system SMTP) and is then never in the response
(`email_failed: true` if the send failed — the owner uses forgot-password);
only when email cannot be sent is `setup_token` returned, once. The creation is
written to the organization's audit log as `user.created` by
`platform-admin:<email>`. The owner created with `POST /api/v1/admin/tenants`
follows the same delivery rule.

**Owner recovery.** When every owner of an organization is suspended, a
super admin can send `{"email": "...", "name": "...", "recovery": true}` to the
same endpoint to create a new owner (RFC-022 revision 7). It is refused with
403 for any other console role, with 409 while any owner is active, and with
400 when the organization cannot send email: the recovery link is **only
emailed, never returned**. The suspended owners are left as they are. The
request is audited as `organization.owner_recovery` in `admin_audit_logs` (high
severity, refusals included) and as `user.created` with `owner_recovery: true`
at critical severity in the organization's audit log.

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
`X-Forwarded-For` only when the peer is in `SERVER_TRUSTED_PROXIES`
(`pkg/httpsec.ClientIP`, the one place that reads those headers). From a trusted
peer it walks `X-Forwarded-For` from the right, skipping entries that are
themselves trusted proxies, and takes the first untrusted one (entries left of
it were written by the client and are never believed). A well-formed
`X-Real-IP` is used only when `X-Forwarded-For` is absent, because a proxy that
ignores `X-Real-IP` (Caddy's `reverse_proxy` by default) passes the client's
value through. A trusted proxy must therefore set or append `X-Forwarded-For`,
and every proxy hop between the client and the API belongs in
`SERVER_TRUSTED_PROXIES`. When users reach the API through the UI's
Next.js proxy, the peer is the UI container, so:

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
| `TENANT_CREATION_MODE` | `admin_only` | Only the platform administrator creates organizations (console, `bootstrap-admin -org-*`). `self_service` (opt-in, SaaS/trial): any signed-in user may, through create-first-team and `POST /tenants`. Anything else fails startup. |
| `SSO_ENTRA_DEFAULT_ROLE` | `viewer` | JIT role for the env Entra fallback. |
| `SMTP_*`, `SMTP_BASE_URL` | — | When set, set-password links are emailed (`<SMTP_BASE_URL>/set-password?token=`). |
| `SERVER_TRUSTED_PROXIES` | empty | Peers whose forwarding headers are trusted (IP allowlist, rate limits, audit). |

## Code map

| Piece | Where |
|-------|-------|
| Account provisioning service | `internal/app/tenant/user_provisioning.go` |
| Organization + owner (console and `bootstrap-admin`) | `internal/app/tenant/organization_creator.go`, `internal/adminbootstrap/organization.go` |
| Membership role derivation, exact role grant | `internal/app/accesscontrol/membership_role.go` |
| Domain / IP policy | `pkg/domain/tenant/security_policy.go` |
| IP allowlist middleware | `internal/infra/http/middleware/ip_allowlist.go` (wired in `routes/routes.go`, `routes/tenant.go`) |
| Registration gate | `AuthService.Register` / `pendingInvitationFor` (`internal/app/auth/service.go`) |
| SSO admission | `SSOService.jitProvisioningAllowed` (`internal/app/auth/sso.go`) |
| Set-password email | `EmailService.SendAccountSetupEmail`, template `account_setup` |
