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
| Invitation | `POST /api/v1/tenants/{tenant}/invitations`, then register with `invitation_token` (if no account) and `POST /api/v1/invitations/accept` with `{"token"}` in the body | owner/admin to invite; the token + matching email to accept |
| Organization SSO (OIDC/SAML JIT) | `/api/v1/auth/sso/*`, `/api/v1/auth/saml/{org}/*` | provider active + auto-provision + DNS-verified domain **with purpose `sso`** (set up in the admin console; a domain the organization verified itself for EASM never admits users, research/22 E6) + allowed domains |
| Self-registration (email, or the first Google/GitHub/Microsoft sign-in) | `POST /api/v1/auth/register`, `/api/v1/auth/oauth/*` | the sign-up policy is `self_service`, or a pending invitation for the email ([Admission](#admission-one-rule-for-every-path)) |

## Sign-up ceiling

The deployment's server configuration sets a **ceiling** that no API can
change ([RFC-104](../rfcs/RFC-104-signup-modes-and-joining.md)):

| `SIGNUP_MODE` | Meaning |
|---------------|---------|
| `disabled` (default) | No public account creation of any kind. Accounts come from a platform administrator, an invitation or an organization's SSO; organizations from a platform administrator. |
| `domain` | Public sign-up only for addresses on an organization's verified domain; such a person joins that organization and never creates one. |
| `open` | Anyone may sign up and create an organization (the hosted service), within the console policy and the limits. |

The console policy below is a runtime switch **under** the ceiling. The
policy in force is the stored policy clamped to the ceiling
(`signup.Ceiling.Clamp`): with `disabled` or `domain`, a stored
`self_service` acts as `admin_only`, and `PUT /api/v1/admin/settings/signup`
with `self_service` answers 409 `SIGNUP_LOCKED_BY_DEPLOYMENT` before the
authenticator code is checked. Opening sign-up therefore needs two keys: the
server configuration and a super admin with a fresh authenticator code. A
stolen console session cannot open registration on a closed deployment.
Lowering `SIGNUP_MODE` closes sign-up at the next start with no console change.

Start-up refuses to run when:

- `SIGNUP_MODE` is not `disabled`, `domain` or `open`;
- `SIGNUP_MODE=domain` or `open` and the platform e-mail (System > E-mail) is
  not set: every self-registered address must be verified. Set it with
  `bootstrap-admin` (`BOOTSTRAP_SMTP_*`), or start with `disabled`, set it in
  the console and restart. While running, public sign-up is also closed
  whenever the e-mail settings stop working;
- `SIGNUP_MODE=domain` or `open` with `AUTH_PROVIDER=oidc` (no local accounts);
- `SIGNUP_MODE=open` with `APP_ENV=production` and no
  `CAPTCHA_TURNSTILE_SECRET`/`CAPTCHA_TURNSTILE_SITE_KEY`, unless
  `SIGNUP_CAPTCHA=off-i-understand` accepts open sign-up without a CAPTCHA;
- the retired `TENANT_CREATION_MODE` is still set (`admin_only` is
  `SIGNUP_MODE=disabled`, `self_service` is `SIGNUP_MODE=open`).

A deployment with `domain` or `open` logs a WARN line at every start.

### Email verification of self-registered accounts

Under `domain` and `open` every account created by self-registration (no
pending invitation for that exact address) verifies its address before it can
sign in. The verification rule is decided before the account lookup, the same
way for a new and an existing address, so it does not enumerate.

- An organization's `security.email_verification_mode` governs only the
  accounts **invited** into that organization (the invitation proves the
  mailbox, so an invited registration is verified at once). It never decides
  public sign-up: there is no "the only organization is the default" rule, and
  an invitation token for another address does not make its organization's
  setting apply.
- Missing SMTP never skips verification there. Start-up refuses `domain`/`open`
  without the platform e-mail, and sign-up closes at run time without it.
- Under `disabled` only invited and administrator-created accounts exist; the
  organization setting, then the platform e-mail (auto: no e-mail, no
  verification) and `AUTH_REQUIRE_EMAIL_VERIFICATION` apply as before.

## Sign-up policy (Console > System > Sign-up)

Who may create an account and who may create an organization on this
deployment is **one platform setting** with two decisions, `signup_policy` in
`platform_settings` (migration 001313), edited in the admin console:

| `accounts` | Who may create an account by public sign-up |
|------------|---------------------------------------------|
| `closed` (default) | Nobody. Accounts come from an administrator, an invitation or an organization's SSO/SCIM. |
| `domain` | Only an address on a domain an organization verified and opened to joining; the account joins that organization and never creates one. |
| `open` | Anyone (not a disposable address). |

| `mode` | Who may create an organization |
|--------|--------------------------------|
| `admin_only` (default) | Only a platform administrator (console, `bootstrap-admin -org-*`). |
| `self_service` | Anyone signed in (create-first-team, `POST /tenants`). Needs `accounts: open`. |

`accounts: open` with `mode: admin_only` lets the hosted service keep sign-up
open while it pauses organization creation (an abuse wave). A policy stored
before `accounts` existed reads as `open` with `self_service` and `closed`
otherwise.

Plus `request_access`: whether people who cannot sign up may ask for an
organization (the request queue follows in its own change).

- **Who reads it.** create-first-team, `POST /tenants` and
  `GET /auth/providers` (`tenant_creation_mode`, which the web uses to offer
  "create organization"; `registration_enabled` and `signup_accounts`, which
  decide "Sign up") read it per request (`signup.Service.Current`,
  cached 15 s per replica).
- **Fail-closed.** Nothing stored or a read error means `admin_only`.
- **Ceiling.** The value in force is clamped to `SIGNUP_MODE` (see
  [Sign-up ceiling](#sign-up-ceiling)). `GET` reports the stored
  `mode` and `accounts`, the `deployment_mode`, `max_accounts`,
  `self_service_locked`, and the `effective_mode` and `effective_accounts`;
  the console shows the choices above the ceiling locked with the reason.
- **Seeding.** `SIGNUP_MODE` seeds the first value at start-up when no row
  exists (`source: environment`), the widest the ceiling allows: `open` seeds
  `accounts: open` + `self_service`, `domain` seeds `accounts: domain` +
  `admin_only`, `disabled` seeds `closed` + `admin_only`. After that the stored value wins (still clamped); the console
  shows where the value came from.
- **Changing it.** `PUT /api/v1/admin/settings/signup` with the version that
  was read (409 when another administrator saved since) needs a **super admin**
  and a **fresh authenticator code** (`STEP_UP_REQUIRED` / 401 without or with
  a wrong one). Every change writes a **critical** admin audit row
  (`platform.signup_policy_changed`, before and after), a WARN line with
  `alert=signup_policy_changed`, and emails every other active administrator.
  Any administrator may read it (`GET`).
- **No lock-out.** A mode change never touches existing organizations,
  members, invitations or sessions; it decides only who may create a new
  organization from then on.

### Admission: one rule for every path

Every path that would write an account or an organization asks one function,
`signup.Admit` (`pkg/domain/signup/admit.go`), so the paths cannot drift:

| Creating | Admitted when | Path |
|----------|---------------|------|
| an organization | the policy in force is `self_service` (so `accounts: open`) | create-first-team, `POST /tenants` |
| an account | **refused first** (`sso_required`, nothing written) when the address is on a domain whose organization requires its SSO, except through that SSO itself | register, first social sign-in |
| an account | an organization's SSO admits the identity (JIT: auto-provision, DNS-verified SSO domain, allowed domains), in either mode | OIDC/SAML callbacks |
| an account | a pending invitation is addressed to the email, in either mode | register with the invitation token; a social sign-in whose verified email has a pending invitation |
| an account | `accounts: open` and the email is not on a disposable-address service (`pkg/emaildomain`) | register, first social sign-in |
| an account (`domain_account`) | `accounts: domain`, the verified email is on a joinable domain of an organization, not disposable; the account joins that organization by its join policy and never creates one | register, first social sign-in |

Anything else is refused **before anything is written**: no `users`,
`sessions`, `refresh_tokens` or membership row. Register and the social
callback answer one refusal, 403 `SIGNUP_NOT_AVAILABLE` ("Your organization
isn't set up yet"), whatever the reason, and the web sends the person to
`/not-set-up` (en/vi), which names no organization. An account that already
exists signs in as before: a mode change never locks anyone out.

`AUTH_ALLOW_REGISTRATION` and `TENANT_CREATION_MODE` are retired: start-up
refuses to run while either is set and names `SIGNUP_MODE` instead.

### Domain sign-up policy (Settings > Domains, owner only)

An organization that holds a domain **verified for SSO** (exclusive
platform-wide, DNS TXT, set up by the platform administrator) decides what
that claim does to accounts on the domain. Every effect is **off by default**
and applies only while the claim is verified and unambiguous: a lapsed claim
(DNS proof gone) or a claim in conflict stops every effect at once.

| Setting | Effect |
|---------|--------|
| `join_policy` `off` / `approval` / `auto` | Whether a verified holder of an address on the domain may ask to join (`approval`) or joins at once (`auto`); with `accounts: domain` this is what admits a public sign-up (`domain_account`) |
| `join_role` `viewer` / `member` | Role of people who join by domain; never an administrator |
| `discoverable` | Show the organization to verified holders of the domain during onboarding |
| `sso_required` | Refuse password and social sign-up for addresses on the domain (403 `SSO_REQUIRED`, nothing written); they come in through the organization's SSO. Needs a working SSO connection |
| `block_new_workspaces` | Accounts on the domain cannot create organizations (create-first-team, `POST /tenants`) |
| `include_subdomains` | The effects also cover `*.domain` addresses; the exact claim of a subdomain wins |

- `GET /api/v1/organization/settings/domains` (owner or admin) lists the
  organization's domains with their policy and `effective`.
- `PUT /api/v1/organization/settings/domains/{domain_id}/signup-policy`
  (owner, step-up) changes it; audited as
  `sso.verified_domain_signup_policy_changed` (high). A domain id of another
  organization answers 404.
- **Existing accounts.** The first time `sso_required` or
  `block_new_workspaces` turns on, every active account on the domain outside
  the organization gets its own e-mail naming only the domain (once,
  `capture_notified_at`). Nothing is moved: the account's other organizations
  and data stay its own and are never shown to the claimant.
- An unreadable domain policy refuses the sign-up or the organization
  creation (fail-closed).

### Request access

When the policy is `admin_only` with `request_access` on, the "not set up"
page offers **Request access** (`/request-access`, en/vi):

- `POST /api/v1/auth/access-requests` `{company, email, note, captcha_token?}`
  (public, registration rate limit) answers 202 with one message for every
  accepted submission. Over the per-address limit (3 an hour, the IP kept only
  as a hash) or the per-domain limit (5 a day), or from a disposable-address
  service, the request is dropped silently, so the answer reveals nothing.
  Closed (`self_service`, or requests off): 403 `SIGNUP_NOT_AVAILABLE`.
- With SMTP, the request waits as `unconfirmed` until the requester opens the
  emailed link (`/request-access/confirm#token=…`; the token travels in the
  fragment and then in the body of `POST /auth/access-requests/confirm`,
  single use, 24 hours). Without SMTP it is `pending` at once.
- Console > Organizations > Access requests (any admin reads;
  **ops_admin+** decides, admin-audited `access_request.approve` /
  `access_request.reject`): **Approve** creates the organization with the
  requester as owner through the same creator as "Register organization" (a
  new account gets the one-time set-password link) and only for a confirmed
  request; two administrators approving at once create one organization.
  **Reject** sends a neutral email to a confirmed requester.
- Retention (`access-request-retention` controller, hourly): unconfirmed
  requests are deleted after 24 hours, decided ones after 90 days.
- CAPTCHA: `CAPTCHA_TURNSTILE_SECRET` makes the API require a Cloudflare
  Turnstile token on request-access submissions **and on self-service
  registration** (`POST /auth/register`, `captcha_token`, checked before the
  account lookup, 400 `CAPTCHA_FAILED`). `CAPTCHA_TURNSTILE_SITE_KEY` is
  published as `captcha_site_key` on `/auth/providers`, and the register and
  request-access forms render the check when it is set. The two variables
  must be set together; the server refuses to start with only one. The web
  CSP allows `frame-src https://challenges.cloudflare.com` for the widget.
  Set both whenever self-service sign-up is on in production.

### Invitation tokens stay out of URLs

The invitation token is a bearer credential (whoever holds it can see and
decline the invitation; accepting also needs the invited email). It never
appears in a URL a server or proxy records (RFC-041 §3.2 P4):

- The emailed link is `{APP_URL}/invitations#token=...`. A fragment is never
  sent to a server or put in a `Referer`. The web page reads it, keeps it in the
  tab's `sessionStorage` (so it survives the trip through `/login` or
  `/register?returnTo=/invitations`), and removes it from the address bar and
  history with `history.replaceState`.
- The API takes the token in the JSON body: `POST /api/v1/invitations/lookup`,
  `/accept`, `/accept-with-refresh` and `/decline`.
- Links sent before this change (`/invitations/{token}`) still work: the web
  page redirects them to the fragment form. The API aliases
  `/api/v1/invitations/{token}/...` answer with `Deprecation`/`Sunset`
  headers until 2027-01-15 and are counted in
  `deprecated_route_requests_total{plane="auth"}`.
- For those legacy paths, the API access log, HTTP metric labels and trace
  attributes record `/api/v1/invitations/{redacted}/...`
  (`middleware.RedactPath`), and the gateway's access log records
  `REDACTED`. No log line records a token or a token prefix.

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

`bootstrap-admin -org-*` follows it too, with one difference: when the send
fails it prints the link once on its standard output, with a warning that the
link is a secret. Whoever runs the command holds the database credentials and
could set any password anyway, and otherwise the new owner would have no link
until mail works. The link is never written to a log.

**Owner recovery.** When every owner of an organization is suspended, a
super admin can send `{"email": "...", "name": "...", "recovery": true}` to the
same endpoint to create a new owner (RFC-022 revision 7). It is refused with
403 for any other console role, with 409 while any owner is active, and with
400 when the organization cannot send email: the recovery link is **only
emailed, never returned**. The suspended owners are left as they are. The
request is audited as `organization.owner_recovery` in `admin_audit_logs` (high
severity, refusals included) and as `user.created` with `owner_recovery: true`
at critical severity in the organization's audit log.

### Ownership transfer (RFC-095 §3.5)

The owner hands the organization to an existing member from Settings >
Members (Transfer ownership). The member must be an active person with
two-factor authentication on and not managed by another organization; an
outside member no organization manages becomes internal, after the owner
confirms it. The owner re-authenticates to ask and chooses what they become
(administrator by default, or member or viewer). The member accepts on the
Members page with their own re-authentication within 72 hours, or declines;
the owner can cancel until then. Accepting changes both memberships in one
transaction that ends with exactly one owner. Both people are emailed at each
step and the audit log records it. The owner can never be demoted, suspended
or offboarded any other way.

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

The user opens `<UI>/set-password#token=<setup_token>` and chooses a password
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

### Password policy

A password that is set, reset or changed must be at least
`AUTH_PASSWORD_MIN_LENGTH` characters (default **12**), meet the composition
rules (`AUTH_PASSWORD_REQUIRE_*`), and must not be on the embedded list of the
most used breached passwords (`pkg/password/common.txt`, about 47,000 entries
from the SecLists Pwdb top 100k, matched case-insensitively, no network call).
Existing passwords are not re-checked; the sign-in form takes them as typed.

### Anti-enumeration on the public endpoints

No public sign-in endpoint tells an unauthenticated caller whether an email
has an account or an organization exists:

| Endpoint | Unknown and known answer the same way |
|---|---|
| `POST /auth/login` | 401 "invalid credentials" for an unknown email, a wrong password, a federated account and a locked one (the state is told only to the password holder); a dummy bcrypt runs on every refusal. With Turnstile keys, after 3 failed sign-ins from one client address in 15 minutes the next attempt from it answers 403 `CAPTCHA_REQUIRED` until a passing `captcha_token` is sent (counted per address, never per account, in Redis across replicas; the count only decays with its window, a success does not clear it, and an unreadable counter asks for the CAPTCHA) |
| `POST /auth/register` | 201 with the same body for a new and an existing email: no account id, the verification rule a new account would get, one message; the password policy is checked first for both; the verification email is sent after the response |
| `POST /auth/forgot-password` | 200 "if the email exists…"; the lookup, the token write and the email all run after the response |
| `GET /auth/sso/providers?org=` | 200 `{"providers":[]}` for an unknown organization, like one without SSO; the same provider query runs either way |
| `GET /auth/sso/{provider}/authorize?org=` | 404 "SSO provider not configured" for an unknown organization and a missing provider alike |
| `GET /auth/saml/{org}/metadata` | SP metadata for any well-formed slug (it is built from the slug and the deployment URL only) |
| `POST /auth/discover` | `{"next","org"}` for every email; `sso` + an opaque, expiring organization reference (never the slug) only for a domain an organization proved it owns and signs in to by SSO (sso-authentication.md, "Email-first sign-in") |
| `POST /auth/create-first-team`, `POST /tenants` | a taken and a reserved organization URL get one "this URL is not available" answer that does not echo the slug |
| `GET /auth/saml/{org}/login`, `POST …/acs` | every failure redirects to `/login?error=saml` |

Tests: `tests/unit/auth_anti_enumeration_test.go`.

### Plan of a self-service organization

An organization a person creates themselves starts on the **Free** plan, and
one person owns at most the Free plan's `free_teams_per_user` (1 by default):
another `POST /api/v1/tenants` is refused with 403 `PLAN_LIMIT`. See
`docs/architecture/plans-and-limits.md`.

## Data region (RFC-104)

`DEPLOYMENT_REGION` names the data region of the deployment (1-32 lowercase
letters, digits or hyphens; validated at start). Every organization created
here gets it in `tenants.region` (migration 002571), at insert, and keeps it
for its life: no update writes the column, and a later change of
`DEPLOYMENT_REGION` never moves an existing organization. Organizations from
before have no region. The region is shown on the create form
(`deployment_region` on `GET /auth/providers`) and in the organization's
settings (`region` on the organization). With a second region, each region
runs its own deployment; the selector appears only then.

## Organization access policy (Settings → Organization → Security, owner only)

### Who may be invited (`security.invitees`, RFC-095)

`any` (the default), `verified_domains` (the organization's verified
domains), or `allow_list` (verified domains plus `security.allowed_domains`).
It applies when an invitation is sent and again when it is accepted.
`allow_list` admits the organization's verified domains too: before this
setting, a non-empty `allowed_domains` admitted only the listed domains for
invitations. Verified domains are the organization's own, so this widens
nothing beyond its people; list them in `allowed_domains` as well to keep the
old behaviour obvious.

### Allowed email domains (`security.allowed_domains`)

Empty = no restriction. Otherwise the email's domain (after the last `@`,
case-insensitive, exact — `corp.com` does not admit `eu.corp.com`) must be in
the list for: administrator-created users, adding an existing user, SCIM
provisioning, and SSO just-in-time provisioning, and for invitations when
`security.invitees` is `allow_list` (an organization that set allowed domains
before `invitees` existed reads as `allow_list`). Existing members are not
removed when the list changes.

### Invitation lifecycle (RFC-095)

| Rule | |
|---|---|
| Token | 32 random bytes, stored hashed, in the URL fragment and request bodies only, bound to the invited address, 7 days, single use (acceptance updates only a row with `accepted_at IS NULL`) |
| Preview | `POST /api/v1/organization/invitations/preview {email, role_ids}` (owner or administrator with `members:invite`, the same requirements as creating one; the route takes the organization from the token) says, before sending, whether the policy allows it (reason code), whether the person is outside or personal, whether the roles need the inviter's step-up and the member's two-factor, whether an end of access is required, and whether they are already a member or invited. Nothing about other organizations |
| Resend | rotates the token; at most once every 10 minutes and 5 times per invitation (429 `INVITATION_RESEND_TOO_SOON`) |
| Cancel and decline | the row is kept as revoked (`revoked_at`): the token, the pending list and resend stop working; purged after 30 days. Removing a member revokes their pending invitations the same way |
| Daily plan limit | counts every invitation created in the last 24 hours, revoked ones included |
| Per inviter | at most 50 invitations an hour (429 `INVITATIONS_RATE_LIMITED`) |
| Seats | checked when the invitation is created (members plus pending invitations) and again at acceptance |
| Pending list | shows `member_kind` (internal or external at creation), `privileged` (two-factor will be required), the end of access, the last send and the resend count |
| Acceptance | re-classifies the invitee and re-authorizes the invitation as the inviter (RFC-095 §3.2); both acceptance paths run the same code |


Teams: an invitation can add the person to up to 20 teams (data access), so
they do not join with no data. The inviter can add only teams they may add a
member to (a team carrying a privileged role needs the owner, with step-up),
and the check runs again at acceptance; a team carrying a role above member
counts toward the outside-member two-factor rule.

### IP allowlist (`security.ip_whitelist`)

Empty = no restriction. Otherwise every request made with a user's access token
or one of the organization's `oct_` API keys must come from a listed IP or CIDR,
or it gets `403 {"code":"IP_NOT_ALLOWED"}`. Applies to the organization in the
URL (`/api/v1/tenants/{tenant}/...`) or, elsewhere, the organization the token
or key belongs to. Changes take effect within 30 seconds on every API instance
(immediately on the one that saved them).

| Surface | Allowlist | Why |
|---|---|---|
| User sessions (REST, WebSocket upgrade) | enforced | the people the policy is for |
| `oct_` API keys on the tenant REST API | enforced | automation acting as a member |
| `oct_` API keys on `POST /api/v1/mcp` | enforced | same key, same policy as REST (23b S-H2) |
| Sensor keys (`/api/v2/sensor`) | not applied | sensors run in scan zones and customer networks; own enrollment, key and egress controls |
| SCIM (`/scim/v2`) | not applied | the caller is the organization's IdP (a SaaS whose egress is not the users' network); gating it would also block deprovisioning. The owner-minted SCIM token is the boundary |
| Inbound integration webhooks (Jira) | not applied | sent from the vendor's cloud, authenticated by the per-tenant webhook secret |
| Platform admin console, public routes, platform administrator | not applied | not an organization's members |

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
3. set `SERVER_TRUSTED_PROXIES` on the API to the UI's (and the gateway's)
   own addresses.

**Behind the built-in gateway** the API needs only the gateway (and the UI) in
`SERVER_TRUSTED_PROXIES`. The gateway resolves the client itself, believing a
front proxy's header only when that proxy's address is in
`OPENCTEM_TRUSTED_PROXIES`: `X-Forwarded-For` read right to left by default, or
the header named in `OPENCTEM_CLIENT_IP_HEADERS` (`Cf-Connecting-Ip` behind a
Cloudflare Tunnel connector, whose edge sets it to the one visitor address).
It then overwrites both `X-Forwarded-For` and `X-Real-IP` with that one address
and drops `Cf-Connecting-Ip` / `True-Client-Ip`, so the API never sees the front
proxy's list. Passing that list on (with the front proxy's own address
appended, as a reverse proxy does by default) made the API, which does not
know the front proxy, record the proxy as the client of every request.

List addresses, not a whole container network: every host in a trusted range
can set the client address the API believes (login rate limits, audit
addresses, IP allowlists), including a sensor container running third-party
tools on the same network. The API logs a `SECURITY:` warning at startup, and
`server -check-config` prints one, for any `SERVER_TRUSTED_PROXIES` or
`SENSOR_MTLS_TRUSTED_PROXIES` range wider than 16 addresses (an IPv4 `/28`).
The shipped Compose file pins the gateway and web addresses on its fixed
subnet; give your containers fixed addresses the same way.

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
| `SIGNUP_MODE` | `disabled` | The sign-up **ceiling** (see [Sign-up ceiling](#sign-up-ceiling)): `disabled`, `domain` or `open`. Seeds the console policy on the first start; the policy in force never exceeds it. Anything else fails startup. |
| `SIGNUP_CAPTCHA` | — | `off-i-understand` accepts `SIGNUP_MODE=open` in production without Turnstile keys. |
| `SSO_ENTRA_DEFAULT_ROLE` | `viewer` | JIT role for the env Entra fallback. |
| `SMTP_*`, `SMTP_BASE_URL` | — | When set, set-password links are emailed (`<SMTP_BASE_URL>/set-password#token=`). |
| `SERVER_TRUSTED_PROXIES` | empty | Peers whose forwarding headers are trusted (IP allowlist, rate limits, audit). Pin the proxies' addresses; a range wider than 16 addresses is warned about at startup. |

## Code map

| Piece | Where |
|-------|-------|
| Account provisioning service | `internal/app/tenant/user_provisioning.go` |
| Organization + owner (console and `bootstrap-admin`) | `internal/app/tenant/organization_creator.go`, `internal/adminbootstrap/organization.go` |
| Membership role derivation, exact role grant | `internal/app/accesscontrol/membership_role.go` |
| Domain / IP policy | `pkg/domain/tenant/security_policy.go` |
| IP allowlist middleware | `internal/infra/http/middleware/ip_allowlist.go` (wired in `routes/routes.go`, `routes/tenant.go`) |
| Registration gate | `AuthService.Register` / `pendingInvitationFor` (`internal/app/auth/service.go`) |
| Request access | `internal/app/accessrequest`, `pkg/domain/accessrequest`, `handler/access_request_handler.go`, `controller/access_request_retention.go` (migration 001380) |
| Sign-up policy | `internal/app/signup`, `pkg/domain/signup`, `internal/infra/postgres/signup_policy_repository.go`, `handler/admin_signup_handler.go` |
| SSO admission | `SSOService.jitProvisioningAllowed` (`internal/app/auth/sso.go`) |
| Set-password email | `EmailService.SendAccountSetupEmail`, template `account_setup` |
