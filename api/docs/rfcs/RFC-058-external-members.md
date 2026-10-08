# RFC-058: External members and trusted organizations

- **Status:** Accepted (owner delegated GA1–GA28, 2026-10-08). Part 1 (external membership model) in implementation.
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

## 6. Parts still to build

1. **Trusted organizations and home-realm sign-in:**
   - `tenant_trusts` (host owner requests with step-up, home owner accepts);
   - the assurance decision at token mint and per request:
     - only the home IdP;
     - never weaker than the host;
     - MFA evidence from `amr`/`acr`/AuthnContext, or the home's attestation;
   - role ceiling per trust (admin only if the trust allows it and the owner grants it with step-up);
   - API keys for externals off unless the trust allows them.
   - Plan entitlement: the host needs SSO (Pro/Enterprise).
2. **Policy:**
   - `Security.ExternalMembers` (off / invite-only / trusted-only);
   - personal-account policy (allowed / allowed with MFA, the new-org default / blocked);
   - enforce-SSO exception list;
   - look-alike Gmail warning only.
3. **Home cascade:**
   - home SCIM delete, suspend, offboard, domain lapse, trust revoke or home tenant suspension → external memberships suspended;
   - host notified, audit on both sides;
   - automatic reactivation only for reversible causes.
4. **Domains:**
   - several domains per organization with a per-domain JIT role;
   - lapsed-domain handling: stop JIT, flag members, block email password reset for local accounts on a lapsed domain.
5. **UI:**
   - org switcher (recent, search, external chip, blocked rows with the reason);
   - External members view;
   - Trusted organizations setting;
   - shared member badges (SSO / Domain / External / Personal / Unmanaged / Lapsed / Exception).

Invitation-based cross-organization membership, badges, expiry and the home cascade work on every plan. Trusts, home-realm SSO acceptance and trusted-domain JIT need SSO.
