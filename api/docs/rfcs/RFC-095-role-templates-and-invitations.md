# RFC-095: Role templates and invitations

| | |
|---|---|
| Status | Accepted (owner feedback on the invite dialog, 2026-10-15). Implemented: §2 role templates (minimal built-in roles, versioned library, summaries), §3.1–§3.5 escalation safety and ownership transfer, §4 invitations for people outside the organization, §5 invitation lifecycle with teams on an invitation and the acceptance page, §6 console |
| Scope | api (roles, invitations, token mint), web (invite dialog, roles, accept page, authentication settings) |
| Related | RFC-050 (asset access model), RFC-058 (external members, amended by §4), RFC-065 (bug-bounty programs: the Researcher role), RFC-022 (platform admin console) |

## 1. Summary

An organization starts with four built-in roles and a library of role
templates it copies into its own roles. Every role explains itself with a
risk tier and what it does per product area. Anyone may be invited, to any
role, unless the organization restricts who may be invited; people outside the
organization are always marked as such, and a privileged role for them needs
the inviter to re-authenticate and the invitee to use two-factor
authentication.

## 2. Role templates

### 2.1 Built-in roles

Owner, admin, member and viewer. They are global rows (`tenant_id` NULL) that
every organization sees. Nothing else is built in: a role an organization did
not ask for is noise in every role picker, and its grants change with the
product rather than with the organization's decisions.

The former built-in **Researcher** role (RFC-065) is now the `researcher`
template. Migration `role_template_library` gives every organization that used
it (a member held it, or a pending invitation offered it) its own custom
Researcher role with the same grants, moves every assignment and invitation to
it, and deletes the global row. Organizations that never used it get nothing.
Nobody's permissions change. `researcher` is no longer a reserved slug.

### 2.2 The library

Sixteen templates (`permission.RoleTemplates`), each with personas, a
description and a version: program lead, security analyst, vulnerability
manager, remediation owner, AppSec engineer, CI integrator, scan operator,
sensor operator, validation engineer, external tester, researcher, bug-bounty
triager, threat intelligence analyst, risk approver, auditor and executive.
The table and the invariants the unit tests enforce are in
`docs/architecture/authorization-matrix.md`, section "Role templates".

Templates never carry admin-only permissions, and owner-only powers (deleting
the organization, making administrators, changing peer administrators,
transferring ownership) are checks on the owner, not permissions, so no
template and no custom role can ever hold them.

### 2.3 Create from a template, then edit

`POST /api/v1/roles` takes `template_id`. The role records the template id,
its version and the template's permissions at that version. The permissions
the role carries still come from the request, so the creator may trim them,
and pass the grant ceiling: the creator may only include permissions they hold
(and full data access only if they have it), and admin-only permissions are
refused. The role is the organization's to edit.

### 2.4 Versions and updates

A template's version goes up whenever its permissions or full data access
change; `TestRoleTemplates_VersionPinned` pins each version to a digest of the
grants. A template change never changes an existing role. When the catalog
has a newer version:

- role responses carry `template {template_id, version_taken,
  current_version, update_available, diff {added, removed}}` (role list and
  `GET /api/v1/roles/{id}`, `team:roles:read`);
- `POST /api/v1/roles/{id}/template/apply {version}` (`team:roles:write`)
  applies it: the template's additions are added, its removals removed, the
  role's own edits kept, full data access unchanged. It goes through the role
  update, so the editor ceiling, the admin-only refusal and the guard on roles
  bound to a team apply. A version other than the reviewed one answers 409.
  Audited as a role update with the template version change.

A template removed from the catalog leaves its roles as they are
(`retired: true`).

### 2.5 Summaries instead of permission counts

`permission.Summarize` describes any permission set: a risk tier, the reasons
and, per product area, whether the role views or changes it. Every role and
template response carries it as `summary`.

| Risk | When | Reason codes |
|---|---|---|
| critical | the owner and admin roles (they pass every check) | `admin` |
| high | full data access, managing people, roles or teams, API keys, settings, or secrets | `full_data`, `manage_people`, `api_keys`, `settings`, `secrets` |
| medium | any change, scan run or approval | `run_scans`, `approve`, `delete` |
| low | reads only | |

## 3. Escalation safety

1. **Ceiling on every path.** Creating, editing and updating a role, assigning
   it and inviting with it are bounded by the actor's own permissions and full
   data access (owners are not bounded). The invitation handler's check also
   compares full data access.
2. **Re-authorization at acceptance.** An invitation is a deferred grant. At
   acceptance the roles are granted as the inviter, inside the acceptance; if
   the inviter is no longer an active owner or administrator of the
   organization, or can no longer grant one of the roles (the admin role needs
   the inviter to still be the owner), the acceptance is refused and nothing is
   granted. The invitee asks for a new invitation.
3. **Owner-only powers are not permissions** (§2.2).
4. **Last owner.** The membership owner cannot be demoted, suspended,
   offboarded or lose the owner role; ownership changes only by transfer.
5. **Ownership transfer**: see below.

### Ownership transfer (§3.5)

Ownership is the one power no role carries, so it moves only by an explicit
transfer with an accept step.

| Step | Rule |
|---|---|
| Ask | `POST /api/v1/organization/ownership-transfer` `{member_id, previous_owner_role, confirm_internal}`: the organization's active owner, with a recent re-authentication (step-up). |
| Who can be asked | an active member of the same organization, a person (not a service account), with two-factor authentication on, and not managed by another organization (no home organization). An outside member no organization manages qualifies only with `confirm_internal`: they become an internal member, with no end of access, when they accept. |
| Previous owner | becomes `admin` (default), `member` or `viewer`, chosen when asking; custom roles stay. |
| One at a time | at most one pending request per organization (a partial unique index); a second one is refused until the first is canceled, declined, accepted or lapses. |
| Accept | `POST .../ownership-transfer/approve`: only the member asked, with their own step-up, within 72 hours. Everything is checked again inside one transaction that locks the request and the memberships involved: the person who asked is still the active owner (else the request is void), and the member still qualifies. The previous owner's role changes first, then the member becomes the owner; the transaction ends only if the organization has exactly one owner, by membership and by role. |
| Decline, cancel | `POST .../ownership-transfer/reject` (the member asked) and `DELETE .../ownership-transfer` (the owner). |
| Read | `GET .../ownership-transfer`: the owner who asked and the member asked see the open request; anyone else gets 404. |
| Afterwards | both people's cached membership and permissions are dropped and their permission versions bumped, so tokens minted before re-read the new roles. |
| Record | audit `member.ownership_transfer_requested` (high), `member.ownership_transferred` (critical), `member.ownership_transfer_canceled`, `member.ownership_transfer_declined`; both people are emailed at every step; the member gets an in-app notice when asked; owners and administrators get one when the owner changes. |

The last-owner protection is unchanged: the owner cannot be demoted,
suspended or offboarded, and the error says to use the transfer instead.
Data: `tenant_ownership_transfers` (migration `002206`).

## 4. Invitations for people outside the organization (amends RFC-058 §3)

RFC-058 classified invitees and let people outside the organization join only
as viewers, with no data scope and, when no organization manages their
address, an access end within 365 days (90 by default). That rule kept the
host safe but made the product unusable for organizations whose people use
personal or contractor addresses. It never had anything to do with scanning:
what a member may scan is decided by scope and domain proof, not by their
email domain.

### 4.1 Who may be invited

`Security.invitees`:

| Value | Who may be invited |
|---|---|
| `any` (default) | any address |
| `verified_domains` | addresses on the organization's verified domains |
| `allow_list` | addresses on the organization's verified domains or on `Security.allowed_domains` |

An organization with a non-empty `allowed_domains` from before reads as
`allow_list`, which now also admits its verified domains (before, only the
listed domains): a slight widening, limited to domains the organization
proved it owns. The setting is changed with the other security settings (owner,
step-up, audited). The default is `any` for self-hosted and hosted
deployments alike: a team that signs up with personal addresses must be able
to invite its colleagues, and restriction is the organization's choice.

### 4.2 Any role, with controls that follow the risk

- An outside person may be invited to, or given, any role except owner.
- **Inviter step-up:** inviting an outside address with a privileged role set
  (the admin role, full data access, or a privileged permission: members,
  teams, roles, API keys, secret store, settings), or giving an existing outside
  member such a role, needs a recent re-authentication.
- **Invitee two-factor:** an outside member whose effective grants (direct
  roles and team role bindings) are above member must prove a second factor
  every time a token is minted, including the token the acceptance itself
  mints. Joining a team that carries such a role already needs the owner
  with a recent sign-in, for anyone.
- **End of access is optional.** The inviter may set one. `Security.
  external_access_end_required` (off by default) restores the RFC-058 rule:
  an end within 365 days, 90 by default, for outside people no organization
  manages. Existing end dates stay.
- **Visible everywhere:** the External / Personal / Unmanaged badges on
  members, and now on pending invitations and the acceptance page.
- **Unchanged:** never owner (database CHECK); a trust's `max_role` still caps
  the people of the trusted organization; the personal-accounts policy; the
  home cascade; the service-account ceiling.
- **API keys** follow the member: allowed unless a trust forbids them, and
  never beyond the end of access.
- **Audit:** `invitation.created` records the member kind, whether the role set
  is privileged and whether two-factor is required, at high severity for a
  privileged outside invitee; acceptance notifies owners and administrators of
  privileged grants (existing privilege notices).

### 4.3 Pre-check

`POST /api/v1/organization/invitations/preview {email, role_ids}` (owner or
administrator with `members:invite`, the same requirements as creating an
invitation) answers whether the address may be invited and what
will happen: inside or outside the organization, personal, privileged,
step-up needed, two-factor needed, end of access required, already a member,
already invited, and whether SSO enforcement will need an exception. It says
nothing about other organizations: not whether another organization holds the
domain, nor which.

## 5. Invitation lifecycle

| Rule | |
|---|---|
| Token | 32 random bytes, stored hashed, sent in the URL fragment and the request body only, bound to the address, 7 days, single use (the acceptance update requires `accepted_at IS NULL`) |
| Resend | rotates the token; at most once every 10 minutes and 5 times per invitation |
| Revoke and decline | keep the row as revoked (who, when, why) instead of deleting it; purged after 30 days |
| Daily plan limit | counts invitations sent in the last 24 hours, revoked ones included, under a per-organization lock |
| Rate limit | per inviter and per organization on create and resend |
| Seats | checked when the invitation is created (members plus pending invitations) and again at acceptance |
| Existing account | the invitee signs in as the invited address; other memberships are untouched and the host learns only a home organization's name |
| SSO and SCIM | invitations stay possible; SSO enforcement then needs an exception or a trust for an outside person, which the pre-check reports |
| After removal | an offboarded person may be invited again and starts from nothing; a suspended one is reactivated instead |
| Teams | the inviter may add the invitee to up to 20 teams (`group_ids` on create and preview), so a newcomer does not join with no data. Each team follows the rules for adding a member to it, for the inviter: same organization, active, every role it carries grantable by the inviter, a team carrying a privileged role only by the owner (with step-up), an external team only with an end of access (which the team membership takes), never full data access through a team for an outside person. A team carrying a role above member makes an outside invitee privileged (inviter step-up, invitee two-factor), like the role itself. At acceptance the teams are checked again for the inviter; a team they can no longer add to, or one deleted since, voids the invitation and nothing is granted. Migration `002186`. |
| Acceptance page | organization, inviter, the roles with their risk, outside-member notice, end of access, and the two-factor step when required |

## 6. Console

- Invite dialog: one primary role (system roles, then custom roles) and
  optional additional roles; each role shows its risk and areas; the email
  field runs the pre-check and explains, before submit, what will happen;
  policy refusals are inline sentences, translated; the end of access appears
  only for an outside person.
- Roles: risk and areas in the table and details; create from a template;
  "update available" with the difference and an apply action.
- Authentication settings: who may be invited, allowed domains, end of access
  required for outside people.
- Every string goes through the translation dictionaries (English and
  Vietnamese).

## 7. Threat model

| Threat | Control |
|---|---|
| An editor or inviter grants more than they hold | ceiling on create, edit, template update, assign and invite (§3.1) |
| A demoted or removed administrator's pending invitation still grants roles | re-authorization at acceptance (§3.2) |
| A template update silently widens existing roles | roles copy templates; updates are explicit, reviewed and bounded (§2.4) |
| A custom role reaches owner powers | owner powers are not permissions; reserved slugs and level checks (§2.2, §3.3) |
| An outside person's mailbox is compromised and used as an administrator | invitee two-factor at every token mint, inviter step-up, badges (§4.2) |
| An organization learns about other organizations through the invite form | the pre-check reports only inside/outside/personal (§4.3) |
| Invitation flooding or quota evasion | rate limits, resend cooldown, revocations still count (§5) |
| A trusted organization's people exceed the agreed ceiling | the trust's `max_role` still applies (§4.2) |
| A hijacked owner session hands the organization away, or a member takes it | transfer needs the owner's step-up, and acceptance the member's own step-up and two-factor authentication (§3.5) |
| Ownership goes to someone another organization controls | a managed member cannot be asked; an unmanaged outsider becomes internal only with the owner's explicit confirmation (§3.5) |
| Two transfers, or a transfer and a cancellation, race | one pending request per organization; acceptance locks the request and memberships and verifies exactly one owner before committing (§3.5) |
