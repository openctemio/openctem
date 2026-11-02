# Platform two-factor floor

The platform sets the lowest two-factor requirement every organization carries (the floor). An organization may
require more, never less. Related: [user two-factor authentication](user-two-factor-authentication.md),
[step-up re-authentication](step-up-reauth.md).

Status: shipped (floor setting, grace, sign-in gate, credential rule, tenant clamp, the console page Settings >
Two-factor with its recommendation card). Designed, not shipped (research 308, D16): passkeys for tenant accounts,
switching the managed-service default to everyone, the impact preview and the host CLI reset.

## The setting

Platform setting `auth.mfa` (console API `GET/PUT /api/v1/admin/settings/auth-mfa`; super admin, fresh step-up,
reason, critical audit, every administrator told):

| Floor | Covers |
|---|---|
| `none` | nobody: organizations decide |
| `admins` | owners, administrators, and members holding a privileged role (`permission.IsPrivilegedRole`, by direct or team grant) |
| `everyone` | every member |

Defaults while nothing is stored (`AUTH_MFA_FLOOR` overrides the code default `admins`):

| Install | Floor |
|---|---|
| Hosted service (`MANAGED_SERVICE=true`) | `admins` |
| New self-managed install | `admins` |
| Upgraded self-managed install | `none`, from a seeded row (migration `mfa_floor_upgrade_seed`, source `migration`) until the operator raises it; the API returns `recommend_raise` so the console shows a card recommending `admins` |

A hosted service ignores the seeded `none` and uses only its time as the start of the grace period, so existing
members there get the full grace from the upgrade. A stored value that cannot be read is an error: the token-mint
gate and the tenant settings save refuse, never treat it as `none`.

## Who needs two-factor in an organization

One helper decides (`auth.mfaRequirementFor`), used at sign-in (password login challenge), at token mint (exchange,
refresh, tenant switch), in the account status and in credential creation:

1. The organization requires it for everyone, or for administrators and the member is one by effective privilege
   (the base-role-only check missed a member holding a privileged role): required, no grace.
2. Otherwise the floor covers the member: required from their due date.

Due date = the later of `effective_from` plus 14 days (existing members) and the account's creation plus 7 days
(new accounts). Both grace lengths are settable (0 to 90 days). Raising the floor sets a new `effective_from`.

Before the due date the member signs in without being gated; the account status carries `grace_due_at` and the
2FA card shows "Required from {date}". After it, the same gate as the organization's own rule applies, with the
same session rules: a session from the organization's own identity provider counts (the IdP owns 2FA) unless the
organization requires proof (`sso_require_mfa_evidence`) and the session has none; a social or foreign-provider
session never counts; an external member at their trusted home organization follows its assurance rules.

## Credentials need a factor from the start

Creating an API key, a service account key, a sensor, a sensor key or enrolment token, a stored secret, or saving an
integration (credentials, Jira webhook secret, notification channel) needs an enrolled factor whenever the
organization or the floor covers the caller, even inside the grace period (`middleware.RequireCredentialFactor`,
mounted after the step-up). A caller without it gets 403 `MFA_ENROLLMENT_REQUIRED` and the web app opens setup. An API
key caller and an external OIDC token (whose provider owns 2FA) are not asked. A test pins the list of routes.

## Organizations may only tighten

`GET /tenants/{tenant}/settings/security` returns `platform_mfa_floor` and the two flags already raised to the
floor (clamped on read; stored rows are never rewritten). Saving a 2FA flag so the result asks for less than the
floor is refused with 422 `MFA_BELOW_PLATFORM_FLOOR`; an unrelated save on an organization stored below a newly
raised floor still works. The Authentication settings page shows the floor and disables the switches it covers.

## Key files

`internal/app/platformmfa` (setting, defaults, due date), `internal/app/auth/mfa_floor.go` (requirement,
credential check), `internal/app/auth/mfa.go` (gate), `pkg/domain/tenant/mfa_floor.go` (floor rules),
`internal/infra/http/middleware/credential_factor.go`, `internal/app/tenant/service.go` (clamp and refusal).
