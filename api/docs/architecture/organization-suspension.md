# Organization suspension and account block

A platform administrator can cut an organization or one account off the
platform at once, without deleting anything: the kill switches for abuse,
non-payment or a legal hold. Both are console actions (Console >
Organizations, Console > Users).

| | Suspend an organization | Block an account |
|---|---|---|
| Stored as | `tenants.status = 'suspended'` + `suspended_at/_by/_reason` | `users.status = 'suspended'` + `blocked_at/_by/_reason` |
| Effect | every credential of the organization is refused; its scheduled work is skipped | the account cannot sign in anywhere; its sessions end; its API keys and MCP tokens stop working |
| Data | kept | kept |
| Who | ops_admin or super_admin, fresh authenticator code, reason | same |
| Audit | critical admin audit row (with the reason) and an entry in the organization's own log (without the reason) | critical admin audit row (with the reason) |
| Undo | lift: everything works again as before | unblock: the account may sign in again (sessions stay ended) |

The platform's own system organization and platform administrator accounts
cannot be suspended or blocked.

## Threat model

- **A member of a suspended organization keeps a credential** (a session
  token, a refresh token, an API key, an MCP token, a sensor key, a SCIM
  token, a CI run token, a webhook secret). Every one of them reaches the
  organization through one decision, the access gate, so none outlives the
  suspension by more than the next request.
- **Replicas disagree.** The gate reads a shared Redis cache that the
  suspension service overwrites on every change; the cached value lives at
  most 60 seconds, so even a failed cache write is bounded. Without Redis the
  gate reads the database on every check.
- **The status cannot be read** (database down). The gate fails closed: the
  request is refused (503 on the HTTP edge), never admitted.
- **Status probing.** The gate runs after the credential is verified: an
  unauthenticated caller, a bad webhook signature or an unverified CI token
  learns nothing about an organization's status. Members see only the fixed
  message "This organization is suspended — contact support"; the reason is
  for platform administrators.
- **A stale save lifts a block.** The user repository's `Update` keeps
  `status = 'suspended'` whatever the entity says (a sign-in stamp or profile
  edit loaded before the block cannot undo it); only the console's unblock
  (`PlatformUserDirectory.SetBlocked`) sets the account active again.
- **Abuse of the switch itself.** ops_admin+ only, a fresh authenticator code
  (route step-up), a reason, a critical audit row. Lifting has the same gates.

## The access gate

`tenant.AccessGate` (`internal/app/suspension.Gate`) answers one question —
may this organization be reached — and every credential path asks it once it
knows the organization:

| Credential | Check |
|---|---|
| Session token, JWT-tenant routes, WebSocket upgrade | `middleware.RequireActiveOrganization`, right after authentication in `buildBaseMiddlewares` |
| Session token on `/api/v1/tenants/{tenant}/...` | `middleware.RequireActiveOrganizationParam`, after the membership check |
| Token mint (`/auth/token`) and refresh | `AuthService.organizationOpen`, before the refresh token is spent, so the member can still open another organization; a backstop in `generateTenantScopedAccessToken` covers every mint path |
| `oct_` API key | the middleware, and `apikey.NewMembershipChecker` |
| MCP OAuth token | `apikey.NewMembershipChecker` on every MCP request |
| Sensor key, multi-key store, signed requests, mTLS | `SensorService.organizationOpen`, after the sensor's own status |
| SCIM token | `scim.TokenService.Authenticate` (403 to the IdP) |
| CI token exchange, CI run token | `cirun.Service.Exchange` (after the workload token verified) and `Authenticate` |
| Inbound Jira and GitHub webhooks | the handlers, after the signature verified |

The GitHub App installation webhook is platform-level: it carries only
installation lifecycle events and is not gated.

At sign-in, a membership of a suspended organization is listed with the
suspended memberships and `organization_suspended: true`, so the web app
shows the message instead of opening the organization.

Open WebSocket connections of a suspended organization close at once, on
every API instance (`websocket.Hub.RevokeOrganization`, revocation reason
`organization_suspended`).

## Scheduled work

A suspended organization's scheduled work is skipped, not deleted:

- the tenant sweeps that iterate `ListActiveTenantIDs` (asset lifecycle,
  finding lifecycle, graph enrichment, threat-model refresh, certificate
  monitoring, EASM digest and DNS checks, audit chain verification);
- due scheduled scans, due report schedules, automatic retests, DefectDojo
  syncs;
- command claims: neither the organization's own sensors (refused at
  authentication) nor shared sensors claim its commands.

After the suspension is lifted, overdue schedules run on their next tick.

## Account block

Block sets `users.status = 'suspended'`, which the sign-in and every
per-request account check already refuse (session tokens through `UserSync`,
API keys and MCP tokens through the membership checker), then ends every
session of the account (refresh tokens and permission caches go with them).

## Operating it

The runbook is in `docs/operations/suspension.md`.

## Tests

- `internal/app/suspension`: gate (cache, fail closed, positive status
  check), service (reason, system organization, conflicts, critical audit,
  cache overwrite, sockets).
- `internal/infra/postgres/organization_suspension_db_test.go`: store, the
  scheduled-work queries, sign-in membership lists, block that a stale save
  cannot lift.
- `internal/infra/http/routes/organization_suspension_db_test.go`: session
  token and API key refused and restored over the real route registration,
  another organization of the same member unaffected, the MCP / API key
  membership check, a blocked account's session and key.
- `internal/app/sensor/organization_suspension_db_test.go`: sensor key.
- `tests/unit/auth_organization_suspension_test.go`: token exchange and
  refresh refused without spending the refresh token.
- SCIM, CI run token, Jira and GitHub webhooks, the middleware and the
  WebSocket revocation: unit tests next to each.
