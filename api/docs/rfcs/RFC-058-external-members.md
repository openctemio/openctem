# RFC-058: External members and trusted organizations

- **Status:** Accepted (owner delegated GA1–GA28, 2026-10-08). Parts 1 (external membership model), 2 (trusted organizations, home-realm sign-in) and 3 (home cascade) in implementation.
- **Related:**
  - RFC-050 (member lifecycle, data scope);
  - RFC-022 (platform admin console);
  - RFC-025 (user onboarding);
  - the exclusive SSO domain claim (one organization per verified SSO domain, migration 001303);
  - accounts keyed on the identity provider's user id (`user_identities`, migration 001306).

## 1. Problem

Accounts are global and memberships are per organization, so one person can belong to several organizations. A typical case is a group's IT engineer who works in the group's sister companies. Three gaps make that unsafe:

1. **Nothing says the person is from outside.** An organization that admits someone it does not manage gets no signal when that person leaves their own company, and no ceiling on what it may grant them.
2. **Strong policies lock them out.** An organization that enforces SSO or 2FA cannot admit an outsider whose session came from their own company's identity provider. The only way round it is to weaken its own policy.
3. **One organization could end another's sessions.** Suspending or removing a member in one organization revoked the person's sessions everywhere. This is fixed separately: cutting a member in one organization keeps their other organizations signed in.

## 2. Concepts

- **Home organization** of an address: the organization that holds the address's email domain verified for SSO. A verified SSO domain has one holder platform-wide. A conflicting legacy claim gives no home.
- **Member kind:**
  - `internal`: the organization holds the member's email domain. This is also the kind of every membership that existed before this RFC, and of colleagues on an unclaimed domain while the organization has verified no domain at all.
  - `external`: anyone else. An external member is either *managed* (they have a home organization) or *unmanaged* (a personal address such as gmail.com, or a work domain no organization has verified).
- **Trusted organization** (part 2): a host organization trusts a named home organization. The home organization accepts the trust (two-sided). External members from that home may then satisfy the host's SSO/2FA policy with a session from their home identity provider, never at a lower assurance than the host requires.

## 3. Rules (part 1, implemented)

| Rule | Where |
|---|---|
| An invitee is classified when the invitation is created and again when it is accepted (the domain may have been claimed or released in between). | `tenant.AddressClassifier`, `TenantService.ClassifyAcceptedInvitation` |
| An external invitee joins as a **viewer** and has **no data scope** until a host administrator adds them to a team. An invitation offering more than viewer is refused; an acceptance re-classified as external grants viewer only. | `CreateInvitation`, `ApplyInviteeClassification` |
| An external member can **never be an owner**: a CHECK on `tenant_members` plus triggers on `user_roles` and on `tenant_members.kind`. The role grant guard also refuses them the admin role and any full-data-access role, on every path (role assignment, role set, bulk assign, invitation acceptance, membership role change). | migration 001316, `RoleService.capExternalTarget`, `UpdateMemberRole` |
| An **unmanaged** external member must have an access end date: 90 days by default, 365 at most. A managed external member may have one (optional). | `tenant.ExternalAccess.Validate`, `SettleExternalAccess` |
| An expired membership is **suspended within a minute** (`suspended_reason = expired`) in its own organization only. Access is cut, the organization's own IdP sessions end, administrators are told, and an audit row is written. | `MemberAccessExpiryController`, `TenantService.ExpireMemberships` |
| An expired member comes back only with a new end date. `PATCH /api/v1/organization/members/{member_id}/access` takes `expires_at` and `reason`, needs owner/admin plus `members:write`, re-enables an expired membership and is audited as `member.access_changed`. A plain reactivation is refused. | `ExtendMemberAccess`, `ReactivateMember` |
| External people join **only by accepting an invitation** addressed to them (their consent). An administrator cannot add an existing account directly, nor create an account for them. The platform administrator's first-owner bootstrap is exempt. | `AddMember`, `UserProvisioningService.CreateUser` |
| The host sees the member's kind and the home organization's **name** only. The access end date and the suspension reason are shown to owners and admins only. | members list (`kind`, `home_organization`, `access_expires_at`, `suspended_reason`) |

Classification fails closed: a lookup error refuses the invitation or the acceptance; it never guesses internal.

## 4. Data (migration 001316, expand-only)

- `tenant_members`:
  - new columns `kind` (default `internal`), `home_tenant_id` (FK, `ON DELETE SET NULL`), `home_domain`, `expires_at`, `expiry_reason`, `suspended_reason`;
  - `chk_tenant_members_external_not_owner`;
  - a partial index on expiring active rows.
- Triggers:
  - `refuse_external_owner_role` on `user_roles`;
  - `refuse_external_owner_member` on `tenant_members.kind`.
- `tenant_invitations`: `access_expires_at`, `access_expiry_reason`. This is the access an external invitee receives.

Every existing membership stays `internal`, so nothing changes for existing members.

## 5. Threat model

| Threat | Control |
|---|---|
| A host grants an outsider owner or admin, or full data access | DB CHECK and triggers for owner; grant guard for admin and full data access; viewer-only on entry |
| An outsider keeps access after leaving their company | Mandatory expiry for unmanaged members. Home cascade for managed members (part 3). |
| An administrator attaches someone else's account to their organization without consent | Externals join only through an invitation addressed to them, accepted while signed in as that address |
| An organization squats on another company's domain by creating accounts there | Account creation for an external address is refused |
| One organization signs a person out of their other organizations | Tenant-scoped revocation (separate change) |
| Information about other organizations leaks to a host | The host learns only the home organization's name; nothing else about other memberships |

## 6. Trusted organizations and home-realm sign-in (part 2, implemented)

| Rule | Where |
|---|---|
| **Two-sided.** A host owner asks to trust the organization that holds a domain verified for SSO (`POST /api/v1/organization/trusts {home_domain, ...}`). That organization's owner accepts (`POST .../{trust_id}/approve {attest_idp_mfa}`). Either owner ends it (`DELETE .../{trust_id}`). All three need owner plus step-up. Only the host changes the settings (`PATCH .../{trust_id}`). A third organization neither sees nor acts on a trust (404). | `orgtrust.Service`, `tenant_trusts` (migration 001320) |
| **A requested trust grants nothing.** A trust never admits anyone by itself: the person still needs an invitation to the host. | `orgtrust.Trust.IsActive` |
| **Home-realm sign-in.** A session counts as an SSO sign-in of the host for an external member when all of these hold: the session was issued by the member's home organization's identity provider; the trust is active and accepts home sign-in; the home still holds the member's email domain; and, if the trust requires it, the provider proved a second factor. This applies at token exchange and refresh. The token's `auth_method` is then `sso`, so the per-request SSO gate agrees. | `AuthService.assuranceAt`, `authMethodAt` |
| **Never weaker than the host.** These never count: a password session, social login, a third organization's identity provider, or a trust that is not accepted. When the host requires 2FA, the home sign-in passes only with MFA evidence on the session or the home owner's attestation that its IdP enforces MFA. | `enforceSSOPolicy`, `enforceMFAPolicy` |
| **MFA evidence** is recorded on the session (`sessions.mfa_evidence`), only from the verified id_token (`amr` contains `mfa`) or assertion (multi-factor `AuthnContextClassRef`). | `oidcMFAEvidence`, `samlMFAEvidence` |
| **Role ceiling.** The trust caps the home's people at `viewer` or `member` (default member). Admin and owner are never possible: a CHECK, plus the grant guard. | `RoleService.capExternalTarget`, `UpdateMemberRole` |
| **API keys.** An external member may create an API key only when the trust allows keys. The key may not outlive the member's access. Unmanaged externals never get keys. | `apikey.Service` + `orgtrust.Policy.APIKeyAllowance` |
| **Default end of access.** The trust may propose one for new members from the home. | `orgtrust.Policy.DefaultExpiryFor` |
| **Ending a trust** suspends, in the host only, every external member homed there (`suspended_reason = trust_revoked`). | `TenantService.SuspendExternalMembersFromHome` |
| **Audit and notices.** Every change is audited at critical severity in both organizations' logs, and both sides' owners and administrators are told. Neither learns anything about the other beyond its name. | `sso.trust_*` audit actions |
| **Plan.** Trusts need single sign-on on the host's plan. The check is wired as an optional entitlement; without the entitlement layer every plan may trust. | `orgtrust.SSOEntitlement` |

Step-up inside the host re-authenticates at the session's identity provider, which is the home's (existing behaviour); the host accepts it like the sign-in.

## 7. Home cascade (part 3, implemented)

The home organization controls the person.

| Cause | Effect | Reversal |
|---|---|---|
| The home disables a member (`/suspend`, SCIM `active=false`) or offboards them (`/offboard`, SCIM delete) | Every external membership homed there, in every other organization, is suspended in its host (`suspended_reason = home_access_ended`). Host administrators are told and the host's log records each suspension. The home's log records how many, with nothing about the hosts' data. When the home holds the person's email domain, every session of the person ends: the organization that owns the identity let them go. | Re-enabling the member at home restores the memberships that the cascade suspended. A membership is not restored when its own end of access passed meanwhile. |
| The home stops holding the domain: its DNS proof lapsed on re-verification, or it removed the domain | Members homed there by that domain are suspended in their hosts (`home_domain_lapsed`). This fails closed: nobody manages them any more. | Proving the domain again restores them. |
| A trust ends | Part 2 (`trust_revoked`) | — |

A host's own suspension of a member is never undone by the cascade: only memberships the cascade suspended, with the cascade's reason, are restored.

## 8. Personal accounts and SSO exceptions (part 4, implemented)

A **personal member** is an external member with a consumer mail address (gmail.com, outlook.com, ...). No organization can hold such a domain, so the person is always unmanaged. They join only by invitation, and their access must end (part 1).

| Rule | Where |
|---|---|
| **Policy.** `Security.personal_accounts` is `allowed`, `allowed_with_mfa` or `blocked`. New organizations default to `allowed_with_mfa`; organizations created earlier keep `allowed` until an owner changes it. The setting is changed through `PATCH /tenants/{tenant}/settings/security`, which needs owner plus step-up and is audited. | `tenant.PersonalAccountsPolicy`, `NewTenant` |
| **Blocked:** an invitation to a personal address is refused, and so is its acceptance; an existing personal member gets no token (`ErrPersonalAccountsBlocked`). Nothing is deleted, so switching back restores access. | `TenantService.requirePersonalAllowed`, `AuthService.enforcePersonalPolicy` |
| **Allowed with MFA:** a token is minted only for a session that proved a second factor: a password session of a user with 2FA on, or a federated session with MFA evidence. | `enforcePersonalPolicy` |
| **SSO exceptions.** `Security.sso_exceptions` names members who may sign in without SSO while it is enforced. Each exception has a reason, ends at most 90 days ahead, and names a current member. It is honoured only with a proven second factor at token mint; the per-request gate honours it too and fails closed on a lookup error. Owner plus step-up. | `SSOException`, `ssoExceptionAllows`, `SSOEnforcementGate.excepted` |
| **Look-alike warning.** Creating an invitation reports `lookalike_of`: existing members whose address reaches the same mailbox once dots and `+tags` are ignored (Gmail) or `+tags` alone (other domains). This is a warning only: identity always stays the exact address, and accounts are never merged. | `TenantService.Lookalikes` |

Not yet: a second factor (TOTP) for social-login accounts, with the challenge at social sign-in. Until then, a Google-only personal member of an `allowed_with_mfa` organization needs a password account with 2FA.

## 9. Several domains and lapsed domains (part 5, implemented)

An organization may verify several SSO domains (one claim per domain, platform-wide; RFC-022). Each domain carries its own just-in-time provisioning (migration 001330).

| Rule | Where |
|---|---|
| **Per-domain JIT.** `jit_enabled` (default on) decides whether SSO may admit newcomers on the domain. `jit_role` (`viewer`, `member`, or empty for the identity provider default) is the role they get. `admin` and `owner` are refused, by the domain entity and by a database CHECK. Set by a platform administrator: `PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}`, audited as `sso.verified_domain_jit_changed`. | `VerifiedDomain.ChangeJIT`, `SSOService.domainJIT` / `jitRoleFor` |
| **Fail closed.** Only a verified SSO domain of the organization admits anyone. A lookup error refuses. | `domainverify.Service.DomainJITPolicy` |
| **Lapsed domain: JIT stops.** Once the DNS proof lapses, the domain is no longer verified, so it admits no newcomers. | as above |
| **Lapsed domain: members flagged.** The members list reports `domain_lapsed` for members whose address is on a domain this organization held and lost. | `ListMembersWithUserInfo` |
| **Lapsed domain: no email password reset.** A forgot-password request for an address on a domain whose verified owner lost it, and that no organization holds now, mails no link: its mailboxes may have changed hands (an expired domain re-registered). The answer is the same as for an unknown address. Recovery goes through an administrator-issued setup link. A lookup error also refuses. | `AuthService.ForgotPassword`, `domainverify.Service.IsLapsedSSODomain` |

Lapsed-domain members keep their access. Their sign-in method (SSO, or password with MFA) is unchanged; the flag lets an administrator review them.

## 10. Console (part 6, implemented)

| Surface | What it shows |
|---|---|
| **Organization switcher** | `GET /users/me/tenants` (and `GET /tenants`) return, for each of the caller's own memberships, `kind`, `access_expires_at` and `blocked_reason`. `blocked_reason` is `suspended`, `expired`, `home_access_ended`, `home_domain_lapsed`, `trust_revoked` or `personal_accounts_blocked`. The switcher marks external organizations, says when access ends, and disables a blocked organization with the reason. It also skips blocked organizations in the keyboard shortcuts and offers a search above seven organizations. |
| **Members** | The list filters on `?kind=internal|external` (the External members view). Shared badges: External (managed by a named organization), Personal, Unmanaged, Lapsed domain, SSO exception, end of access. A disabled member shows why (access ended, left their organization, ...). Owners and admins change an external member's end of access (`PATCH /organization/members/{member_id}/access`). |
| **Invitations** | The invite dialog takes an end of access for people outside the organization (empty: the API proposes 90 days). After creation it shows the look-alike warning and the end of access. |
| **Trusted organizations** | Settings › Organization › Trusted organizations lists the organizations this one trusts and those that trust it. Owners request a trust (domain, highest role, home SSO, MFA proof, API keys, proposed end of access), change its settings, approve an incoming trust (attesting the identity provider's MFA) or end one. Admins read. |
| **Platform administrator console** | The verified domains of an organization show how SSO treats newcomers on each domain (role, or not admitted) and change it (per-domain JIT). |
| **Authentication settings** | Personal accounts policy and, while SSO is enforced, the SSO exception list, saved with the rest of the security settings (owner, step-up). |

## 11. Least-privilege defaults (part 7, implemented)

Every way into an organization starts at the lowest privilege. Raising it is a decision someone takes, is audited and is announced.

| Path | Default and guard | Where |
|---|---|---|
| Invitation, created user | The console preselects the viewer role. Admin is offered only to the owner; the role ceiling and the external viewer-only rule apply as before. | `defaultViewerRoleId`, `CreateInvitation` |
| SSO just-in-time | The role of the domain (part 5), else the identity provider's default, which is viewer for a new OIDC provider and a new SAML configuration. | `jitRoleFor`, `samlprovider.New` |
| SCIM | A provisioned person is a viewer. A group change only applies a role group that matches (mapped, or named member / viewer). Without one the role is kept: nothing is raised, and an administrator falls back to member. | `scim.ProvisioningService`, `reconcileUser` |
| Data scope | No path adds a team or a grant: a newcomer sees no data until a team includes them. | unchanged |
| Raising JIT | An identity provider's default role is changed through an SSO change that an owner approves with step-up. A platform administrator who raises a domain's provisioning (admits newcomers, or a higher role) now also goes through the owner (`domain_jit` change, migration 001327). Lowering it applies at once. | `SSOChangeService.SubmitDomainJIT`, `JITRaises` |
| **Approval mode** | `Security.jit_requires_approval` (owner, step-up). With it on, a newcomer SSO admits gets a membership that is suspended with the reason `awaiting_approval`. Their sign-in answers "waiting for an administrator's approval", and the administrators are told. Approving is re-enabling the member (audited as an approval); rejecting is offboarding. | `Membership.HoldForApproval`, `holdIfApprovalRequired`, `ReactivateMember` |
| **Privilege notices** | Owners and administrators get an in-app notice when a member gains privileges: the membership role raised; the owner, admin or a full-data-access role granted (assign, set, bulk); or a newcomer approved. | `TenantService.NotifyPrivilegeIncrease`, `RoleService.notifyElevated` |

## 12. Parts still to build

1. **Policy:** `Security.ExternalMembers` (off / invite-only / trusted-only).
2. **Home cascade, remaining cause:** the home organization itself being suspended or scheduled for deletion. This waits for the organization states from research/71.
3. **Personal accounts:** a second factor (TOTP) for social-login accounts.
4. **Domains:**
   - include-subdomains on a verified domain;
   - SSO-only suspension of lapsed-domain members after 30 days.

Invitation-based cross-organization membership, badges, expiry and the home cascade work on every plan. Trusts, home-realm SSO acceptance and trusted-domain JIT need SSO.
