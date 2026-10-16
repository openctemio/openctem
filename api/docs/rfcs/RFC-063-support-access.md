# RFC-063: Support access — customer-granted, time-boxed, visible

| | |
|---|---|
| Status | Partially implemented (read-only grants and console support sessions, §11, 2026-10-16); read and write, emergency access and the tenant-tab frame are Proposed |
| Authors | Platform team |
| Related | RFC-022 (platform admin console), RFC-041 (API planes), RFC-050 (asset access model), RFC-058 (external members), plans and limits (`docs/architecture/plans-and-limits.md`) |
| Code | `internal/app/supportaccess`, `pkg/domain/supportaccess`, `internal/infra/postgres/support_*_repository.go`, `handler/support_access_handler.go`, `handler/admin_support_handler.go` |

## 1. Summary

A platform administrator never holds standing access to an organization's
data: administrators belong to no organization (trigger on
`tenant_members`), and the console has no view of findings, assets or
evidence. That invariant stays.

Support still needs to see what a customer sees, for example to answer "why
is this finding ranked P0?". Today that means a shared screen or an operator
in the database. This RFC adds the only sanctioned path:

- **The organization grants it.** An owner opens support access for one case,
  for a bounded time (4 hours by default, 72 hours at most). It is read-only
  unless two owners approve read and write.
- **A support administrator uses it.** That is a console administrator with
  the `support` capability, after a fresh authenticator code. They get a
  short-lived token for that one organization. The token carries a fixed,
  allow-listed support role and is not a membership.
- **Everyone can see it.** A banner shows for every member while a support
  session is open. Every request is in the organization's own audit log as
  `support:<administrator email>` with the case reference. Owners are
  emailed when it starts and ends.
- **Owners can revoke it at once.** The next request of the support session
  is refused.
- **An emergency path exists without consent.** It covers an active security
  incident or a legal order. Two super admins must act, with a reason, for 4
  hours at most, and the owners are told immediately.

## 2. Threat model

| Threat | Control |
|---|---|
| A stolen console session reads customer data | No grant, no access. Starting a session needs the `support` capability **and** a fresh TOTP code. The token lives 15 minutes and is bound to the grant, the administrator and the console session. |
| An insider browses organizations at will | Access needs a grant the organization created for a named case. There is no "all organizations" mode. Every session start and every request is in the organization's audit log, which the customer can see and export. |
| Support quietly changes data | The default is read-only. Read and write need a second owner's approval when the organization has more than one owner. Some actions are refused at any level (§5.3). |
| Exfiltration through exports or secrets | The support role is an allow-list. It has no export, evidence download, secret, credential, API key or integration secret permissions, at any level. |
| A grant outlives the case | The end is mandatory (72 hours at most). Owners revoke it at once. Removing the owner who granted it does not extend it. Revocation is checked on every request, with no cache. |
| Emergency access abused | Two different super admins (requester and approver), each with step-up and a reason. Capped at 4 hours. Owners are emailed at once, and the access is in their audit log. |
| Support identity confused with a member | The token's subject is `support:<admin id>` and is never a `users` row. It cannot be invited, assigned, mentioned or own anything. Membership checks never match it. |
| Customer data in platform logs | The console stores the grant and the session, not the data viewed. Request logs carry the grant id, not response bodies. |

## 3. Grants (organization side)

Settings > Security > Support access (owner only, step-up):

- **Fields:** case reference (1–64 characters), level (`read` or
  `read_write`), duration (1 hour to 72 hours, default 4 hours), optional
  note.
- **Read and write** needs a second owner to approve within 24 hours when the
  organization has more than one owner. With a single owner, that owner's
  step-up is enough, and the grant is flagged in the audit log.
- **The page lists** the active grant, any open support sessions (who, since
  when) and the history. **Revoke** ends the grant and its sessions at once.
- **Entitlement:** the feature is on the Enterprise plan in SaaS. Self-hosted
  organizations are Enterprise (no stored plan), so they have it.

Table `support_grants`:

```
id, tenant_id, case_ref, level, note,
granted_by (users.id), approved_by (users.id, nullable),
starts_at, expires_at, revoked_at, revoked_by, created_at
CHECK (expires_at > starts_at AND expires_at <= starts_at + 72h)
```

It is tenant-scoped like every organization table (composite keys, `tenant_id`
in every query). At most one grant can be active per organization.

## 4. Support sessions (console side)

### 4.1 Who may start one

The support capability is a flag on `admin_users`, set by a super admin and
audited. It is not every administrator. A readonly administrator never has
it.

### 4.2 Starting

Console > Organizations > an organization > **Support access** appears only
while a grant is active. It shows the case reference, level and expiry.

**Start support session** needs the case reference typed again (it must
match) and a fresh authenticator code. The API then:

1. checks the grant (active, not revoked, inside its window) and the
   administrator (support capability, verified console session);
2. creates `support_sessions(id, grant_id, admin_id, console_session_id,
   started_at, ended_at, end_reason)`;
3. mints a tenant-scoped access token: subject `support:<admin id>`, claims
   `tenant`, `support_session`, `support_level`, 15 minutes. It is renewed
   only through the console while the grant and the console session are
   valid;
4. writes `support.session_started` to the organization's audit log and to
   the admin audit log, and emails the owners.

The console opens the tenant application in a new tab with that token. The
tab shows a fixed red frame: "Support session for <organization>, case
<ref>, ends <time>". The frame has an End button.

### 4.3 Enforcement on every request

A support token passes through one middleware placed before the permission
checks:

- the session row exists and is not ended; its grant is active; the console
  session is still valid. This is one indexed query, not cached, so a revoke
  or an ended console session takes effect on the next request;
- permissions come from the support role (§5), never from the JWT body;
- data scope is the organization's full data, read-only for `read`;
- every request appends a tenant audit row (`support.request`: method, route
  pattern, resource id, status). These rows are batched per minute, and
  writes are recorded one by one.

## 5. The support role

### 5.1 Shape

There are two synthetic roles, `support_read` and `support_read_write`,
seeded like the system roles. They are explicit allow-lists, in line with
the "no deny-gate" rule of the authorization model: they are built from read
permissions, plus for read and write the triage writes support uses
(finding status, assignment, comments).

### 5.2 Never granted, at any level

The roles never get:

- exports and report downloads;
- evidence content and attachments;
- secrets, credentials, API keys and integration credentials;
- members, invitations, roles and groups changes;
- SSO, SCIM, MFA and security settings;
- plan, billing and deletion;
- sensor keys and pairing;
- support grants themselves.

### 5.3 Visibility of personal data

Member emails show masked (`j***@acme.com`), except for the case's requester
when the grant names them. The audit log shows support's own actions.

## 6. Visibility

- **Banner.** Every member sees "OpenCTEM support is viewing this
  organization until <time> (case <ref>)" while a session is open. It uses
  the same banner slot as platform announcements.
- **Audit log.** Session start, stop and each request (§4.3) are recorded.
  The organization's audit export includes them.
- **Email.** All owners are emailed at session start and end, and at grant
  creation, approval, revocation and expiry.

## 7. Emergency access

This covers an active security incident affecting the organization, or a
legal order:

- One super admin requests it with the incident or order reference and a
  reason. A **different** super admin approves it. Both use step-up.
- It is read-only and lasts 4 hours at most, with no renewal (a new request
  is needed).
- Owners are emailed immediately, with the reason, and the organization's
  audit log shows `support.emergency_started` with both administrators.
- Platform admins see it in Security > Admin activity at critical severity.
  The overview's attention queue lists open emergency sessions.

## 8. Console

- Organization 360: a Support access tab with the grant state, open
  sessions, history and Start support session.
- Security > Support sessions: every open support session, with End.
- Administrators: the support capability per administrator (super admin
  sets it).
- Overview: open emergency sessions in the attention queue.

## 9. Delivery

| Phase | Content |
|---|---|
| S1 | `support_grants` and the owner UI (grant, approve, revoke, history), entitlement, emails |
| S2 | the `support` capability, `support_sessions`, token minting, enforcement middleware, the two support roles |
| S3 | the banner, audit rows, the tenant tab frame |
| S4 | console pages (organization tab, Security > Support sessions, administrator capability) |
| S5 | emergency access |

Each phase ships tests for:

- a readonly or non-support administrator (refused);
- a revoked, expired or other-organization grant (refused at once);
- a support token on every route outside the allow-list (403);
- cross-tenant use of a grant (404);
- audit and email emission.

## 10. Decisions

| ID | Question | Recommendation |
|---|---|---|
| SU1 | Default and maximum duration | 4 hours default, 72 hours maximum |
| SU2 | Default level | Read-only; read and write needs a second owner when there is one |
| SU3 | Who may use a grant | Administrators with the `support` capability (set by a super admin), never readonly |
| SU4 | Membership or not | Not a membership: a synthetic principal and role, so membership logic never matches it |
| SU5 | Role construction | Allow-list roles (no deny-gate), with the §5.2 list never granted |
| SU6 | Revocation latency | Checked on every request without a cache |
| SU7 | Audit granularity | Session events plus every request, batched per minute for reads |
| SU8 | Plan | Enterprise in SaaS; on by default self-hosted |
| SU9 | Emergency access | Two super admins, 4 hours, read-only, owners told at once |
| SU10 | Personal data | Member emails masked for support, except the case requester |

## 11. Implementation (2026-10-16)

The first delivery is read-only and differs from §3 to §5 in three places,
each for a stated reason.

### 11.1 What is built

- **Grant** (`support_grants`): an owner, with a recent re-authentication,
  names **one platform support administrator by email** (active, `ops_admin`
  or `super_admin`; a read-only administrator can never be named), the data
  scopes (`findings`, `assets`, default both), a duration of 1 to 72 hours
  (default 4), a reason (10 to 500 characters) and an optional case reference.
  The database refuses a window over 72 hours. One active grant per
  administrator and organization.
  - `POST /api/v1/organization/support-access/grants` (owner + step-up),
    `GET …/grants` (owners and admins, history included),
    `DELETE …/grants/{grant_id}` (owners and admins: revoke, ends open sessions
    in the same transaction), `GET …/active` (every member: who, until when,
    which data; the banner).
- **Support session** (`support_sessions`), console side:
  - `GET /api/v1/admin/support/grants`: the live grants naming the caller;
  - `POST /api/v1/admin/support/grants/{grant_id}/sessions`: route-level
    console step-up; the session is **bound to the console session** that
    opened it;
  - `DELETE /api/v1/admin/support/sessions/{session_id}`;
  - reads: `…/sessions/{session_id}/overview`, `…/findings`,
    `…/findings/{id}`, `…/assets`, `…/assets/{id}`.
  - The group requires `ops_admin` or `super_admin`; there is no write route.
- **Enforcement on every read**, one statement, no cache: the session is open,
  belongs to the caller and to this console session, and its grant is not
  revoked and inside its window (server clock). Then the scope is checked.
- **Both audit logs before any data**: the organization's log gets
  `support.accessed` (actor `support:<email>`, route, resource id, session id)
  and the admin log gets `support.accessed` for the organization. If either
  write fails the read is refused (503): no audit, no access. Session start
  and end, grant creation and revocation are in the organization's log;
  refusals (no grant, another console session, scope not granted) are in the
  admin log as `support.refused`.
- **Owners are emailed** on grant creation, revocation, and every session
  start and end.
- **Read model**: an explicit column allow-list. Findings: title, severity,
  status, source, tool, rule, CVE, CWE, asset name and type, file path and
  line, SLA status, first and last seen. Assets: name, type, criticality,
  status, exposure, risk score, finding count, first and last seen. Never
  selected: messages, descriptions, code snippets, secret values, evidence,
  attachments, comments, people's names or emails. Every query is scoped to
  the grant's organization (from the database, never the request); assets of
  private programs and their findings stay hidden (support is no program
  member).

### 11.2 Differences from the proposal

| Proposal | Built | Reason |
|---|---|---|
| A grant for the operator's support, used by any administrator with the `support` capability (§3, §4.1) | A grant names one administrator | the owner decides who looks, not only when; no new capability flag to manage |
| A tenant-plane token for a synthetic principal (§4.2) | Console-plane read routes over a narrow read model | the console has its own origin and listener; a token for the tenant plane would cross origins, and a narrow allow-list is easier to prove than a role over every tenant route |
| `support_read` / `support_read_write` roles (§5.1) | Read-only only; scopes `findings`, `assets` | read and write needs the two-owner approval of §3; not built yet |

### 11.3 Threat model additions

| Threat | Control |
|---|---|
| A stolen console cookie used from elsewhere | the support session is bound to the console session id; the console session itself has its own idle and absolute expiry |
| A support administrator demoted to read-only or deactivated mid-session | the route group requires `ops_admin`+ and the service re-checks the administrator on every read |
| Reads not reaching an audit log under load | both writes happen before the response; a failure refuses the read |
| Cross-tenant ids in a support URL | the organization comes from the live grant; every query carries it (404) |
| Secrets in findings | the read model never selects message, snippet, description or evidence |

### 11.4 Not built yet

Read and write with two-owner approval, emergency access (§7), the tenant tab
frame (§4.2), expiry emails, the console Security > Support sessions page for
all administrators, and the `support` entitlement in SaaS plans.
