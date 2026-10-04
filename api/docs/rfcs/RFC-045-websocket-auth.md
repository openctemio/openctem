# RFC-045: Real-time WebSocket authentication and session binding

> Status: **Accepted** (owner decisions 2026-10-03, §7).
> Scope: `api/` (`internal/infra/websocket`, `/api/v1/ws` route chain, auth
> services' session revocation, permission version), `web/`
> (`src/lib/websocket`, `src/context/websocket-provider.tsx`,
> `server-with-ws.mjs`), the gateway Caddyfile.
> Related: RFC-022 (admin console sessions), RFC-041 (route chains),
> [architecture/authorization-matrix.md](../architecture/authorization-matrix.md#real-time-websocket-apiv1authws-token-apiv1ws),
> [architecture/notification-system.md](../architecture/notification-system.md#real-time-push).
>
> Owner's question (2026-10-03): `GET /api/v1/auth/ws-token` looks redundant;
> is there a better, more secure, more modern way to authenticate the
> real-time socket? Redesign the socket layer to be as secure and as good as
> possible, not only the authentication.

## 1. Answer in short

1. **Authenticate the upgrade with the session cookie**, through the same
   tenant chain as every tenant route (SSO enforcement, organization IP
   allowlist, `RequireTenant`, active membership, read rate limit), behind a
   strict Origin allowlist that also requires an Origin on cookie
   authentication. The browser already sends the `auth_token` cookie on a
   same-origin upgrade; the ticket round trip adds a request and a
   credential in the URL and buys nothing.
2. **Delete the ticket** (`/auth/ws-token`, the ticket service, the ticket
   middleware) and the short-lived **JWT-in-URL fallback**. No ticket for
   cross-site deployments either: the socket is served same-origin by every
   supported topology (gateway, all-in-one, Helm, dev), and a deployment that
   puts it elsewhere must proxy it onto the UI origin.
3. **Bind every socket to its session.** It is closed (code `4401`) at the
   credential's expiry (capped at 15 minutes), when its session is signed out
   or revoked, and when the user's membership or role in its tenant changes,
   on every API instance through a Redis revocation channel.
4. **Harden the socket layer**: per-connection message rate limit, close
   codes instead of silent drops, a proper close handshake, nothing delivered
   after the server decided to close, metrics for connects, refusals and
   forced closes; the web client reconnects with full-jitter backoff,
   refreshes its session on `4401` under a cross-tab lock, and reconnects on
   an organization switch.

## 2. Current state (verified on `develop`, 2026-10-03)

| Area | Code | Finding |
|---|---|---|
| Ticket issue | `routes/auth.go` `GET /auth/ws-token`, `wsTokenMiddlewares`, `LocalAuthHandler.GetWSToken` | Runs the tenant chain, mints a 64-hex single-use ticket in Redis (30 s, `GETDEL`). |
| Upgrade | `routes/misc.go` `registerWebSocketRoutes`, `middleware.WSTicketAuth` | With Redis: ticket only, active membership re-checked. The IP allowlist and SSO enforcement are **not** re-run at upgrade. |
| Fallback | `GetWSToken` → `AuthService.GenerateWSToken` | Without Redis a 30 s JWT is returned and the web puts it in `?ticket=`; the fallback route runs `UnifiedAuth`, which no longer reads query tokens (S-5), so the socket is in fact authenticated by the **cookie** and the JWT only leaks into access logs. |
| Origin | `websocket.NewHandler` `CheckOrigin` | Exact-match allowlist from `CORS.AllowedOrigins`; `*` ignored in production; empty Origin allowed. |
| Session binding | `internal/infra/websocket` | **None.** A `Client` holds only user and tenant. After logout, session revocation, member suspension or removal, a role change or token expiry, an open socket kept receiving the tenant's events until the browser closed it. |
| Revocation store | `redis.SessionRevocationStore`, `auth.markSessionRevoked` | Every session kill path (logout, sign out device/everywhere, password change, 2FA enrolment, user and member suspension, session-limit eviction) writes it, **except OIDC back-channel logout**, whose sessions kept valid access tokens until expiry. |
| Access change | `PermissionVersionService.Increment/Delete` | Bumped on role assign/remove/redefine and member role change; dropped on member removal/suspension. Nothing told the sockets. |
| Channel authz | `Hub.defaultAuthorize` | Per subscribe, against the connection's own user and tenant; broadcast filtered again by tenant and user channel. Correct, but a subscription authorized once stayed authorized for the life of the socket. |
| Limits | `hub.go`, `client.go` | 10 sockets per user per instance (excess closed **silently**, the client reconnects in a loop), 50 subscriptions per socket, 4 KiB messages, 60 s read deadline with server pings. **No message rate limit**: each subscribe costs a permission query, so a socket could be used as a database amplifier. |
| Web client | `web/src/lib/websocket/client.ts` | Exponential backoff without jitter, 10 attempts, no handling of server close codes, a ticket fetch before every connect; the socket stays bound to the old organization after a switch (`tenant-provider.tsx` does not reload). |

## 3. Threat model

Assets: tenant events (finding activity, scan progress, notifications, scope
changes). Actors and attacks:

| # | Threat | Defence (this RFC) |
|---|---|---|
| T1 | Cross-site WebSocket hijacking: a page on another origin opens the socket with the victim's cookie | Exact Origin allowlist; Origin **required** when the credential is the cookie; `SameSite=Lax` cookie (defence in depth only: a sibling subdomain is same-site) |
| T2 | Credential leakage through URLs (proxy and access logs, history, `Referer`) | No credential in the URL at all (ticket and JWT fallback removed) |
| T3 | A signed-out, revoked or expired session keeps streaming | Session binding: close at expiry, on revocation, cross-instance |
| T4 | A suspended or removed member, or a demoted user, keeps receiving events | Access-change revocation closes the user's sockets in that tenant; reconnect re-runs every gate; subscriptions are re-authorized |
| T5 | Gate changes with no event (IP allowlist edit, SSO enforcement switched on, data-scope or group change) | Socket lifetime capped at 15 min (−0–60 s jitter): every gate is re-applied at least that often |
| T6 | Race: revocation published while an upgrade is in flight | The revocation store is written before the broadcast; the handler re-reads it after the hub registered the socket |
| T7 | A forged message on the Redis revocation channel | Can only close sockets that it names exactly (session, or user+tenant), never open or widen one; malformed or unknown-reason messages close nothing |
| T8 | Resource abuse: socket floods, subscribe floods, reconnect storms | Per-user cap with `4429`, per-connection token bucket (10/s, burst 60) then `1008`, 4 KiB frames, read/write deadlines, full-jitter client backoff |
| T9 | Cross-tenant delivery | Unchanged: tenant-scoped channels, broadcast refused without a tenant, tenant and user-channel filter at delivery |
| T10 | Data after close | Once the server sends its close frame nothing more is written or processed |

Out of scope: a compromised browser or XSS in the UI origin (it can open the
socket legitimately); Redis compromise beyond T7 (covered by RFC-040's Redis
ACL work).

## 4. Research

Primary sources; quotes abbreviated.

**Cookies on the handshake.** The WebSocket opening handshake is a fetch with
"mode `websocket`, credentials mode `include`", and `ws`/`wss` are mapped to
`http`/`https` before it ([WHATWG WebSockets](https://websockets.spec.whatwg.org/)).
Cookies ignore ports ("cookies for a given host are shared across all the
ports on that host", [RFC 6265bis §1.3](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)).
`SameSite=Lax` sends cookies cross-site only on top-level safe navigations
(§5.6.7.1), which a handshake never is; under schemeful same-site a `wss://`
connection from `https://` is same-site ([web.dev](https://web.dev/articles/schemeful-samesite)).
So: same-origin and same-site (other port or sibling subdomain) handshakes
carry our Lax cookie; cross-site ones do not, and third-party cookies are
blocked by Safari ([WebKit](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)),
partitioned by Firefox ([Mozilla](https://blog.mozilla.org/en/mozilla/firefox-rolls-out-total-cookie-protection-by-default-to-all-users-worldwide/))
and left to user choice by Chrome ([Privacy Sandbox, 2025-10](https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies)).
Per-browser behaviour was not separately tested; the spec reading is
consistent across them.

**CSWSH.** WebSockets are "not restrained by the same-origin policy"; check
the Origin of the handshake ([Schneider 2013](https://christian-schneider.net/blog/cross-site-websocket-hijacking/)).
A browser "MUST include" Origin ([RFC 6455 §4.1](https://www.rfc-editor.org/rfc/rfc6455.html),
§10.2). OWASP: "Validate the `Origin` header on every handshake. Always use an
explicit allowlist", "Close WebSocket connections when sessions expire",
"When users log out, close all their WebSocket connections immediately",
"Check authorization for each action" ([OWASP WebSocket Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)).
SameSite alone is not enough (sibling subdomains are same-site).

**Credential transport compared.**

| Option | For | Against |
|---|---|---|
| Cookie on the upgrade | No extra request; httpOnly, never visible to JS; no URL credential; reuses the tenant chain | Needs the Origin check (T1); cross-site fails (3PC) |
| Ticket in the URL (current) | Works cross-site | A credential in URLs and logs ("tokens will appear in access logs", OWASP); an extra round trip per connect; a second auth path with its own (weaker) gates |
| Token in `Sec-WebSocket-Protocol` ([Kubernetes](https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/apiserver/pkg/authentication/request/websocket/protocol.go)) | Not in the URL | Misuses the header, must echo a dummy protocol, logged by some proxies; JS-visible token |
| First-message auth (Discord IDENTIFY, Socket.IO `auth`) | Nothing in URL or headers | Unauthenticated sockets exist for a while (needs auth timeout, caps); JS-visible token |

**Mature products.** Rails ActionCable authenticates `connect` from the
cookie, restricts `allowed_request_origins`, and disconnects a user "across
all servers … because it uses the internal channel that all of these servers
are subscribed to" ([Rails API](https://api.rubyonrails.org/classes/ActionCable/RemoteConnections.html)).
Phoenix checks origin and disconnects every socket of a user with
`Endpoint.broadcast("users_socket:" <> id, "disconnect", %{})`
([Phoenix.Socket](https://phoenix.hexdocs.pm/Phoenix.Socket.html)); LiveView
re-validates on reconnect. Socket.IO authenticates "only once per
connection" and disconnects across nodes through the Redis adapter
([socket.io](https://socket.io/docs/v4/server-instance/)). AWS API Gateway
authorizes only `$connect`; changing it "doesn't affect the already connected
client", revocation is a backend `DELETE @connections/{id}`
([AWS](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-lambda-auth.html)).
Slack's RTM URLs are tickets "only valid for 30 seconds" — a design for
third-party clients on another site, not a first-party SPA. The common
pattern: authenticate once at connect, keep an identity → sockets registry,
revoke by broadcasting to every node, and expire.

**Close codes.** 4000–4999 are for private use (RFC 6455 §7.4.2);
graphql-ws uses `4401 Unauthorized` / `4403 Forbidden`
([PROTOCOL.md](https://raw.githubusercontent.com/enisdenjo/graphql-ws/master/PROTOCOL.md)).

**HTTP/2.** RFC 8441 carries Origin and the handshake headers on the
extended CONNECT unchanged ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html));
cookies are ordinary headers. Caddy proxies upgrades as a bidirectional
tunnel ([reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)).
Nothing in this design depends on h1 vs h2.

**SSE instead?** EventSource is server-to-client only
([MDN](https://developer.mozilla.org/en-US/docs/Web/API/EventSource)); our
client subscribes and unsubscribes per channel, which would become separate
POSTs. Workable and it removes CSWSH (CORS applies), but a rewrite of both
ends for no gain once the socket is hardened as below. Not adopted; a fit for
future read-only feeds.

**Reconnect storms.** Use full jitter, `sleep = random(0, min(cap, base·2^n))`
([AWS Architecture Blog](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/)).

## 5. Design

### 5.1 Authentication (PR B)

`GET /api/v1/ws` mounts the same chain the ticket route used to:
`UnifiedAuth` (Authorization header or `auth_token` cookie; session
revocation; session timeout) → user sync → SSO enforcement → organization IP
allowlist → `RequireTenant` → active membership → read rate limit. API keys
(`oct_`) are not accepted: the socket is for user sessions. `ServeWS` refuses
a cookie-authenticated upgrade without an Origin (browsers always send one; a
missing Origin with an ambient cookie is not a browser we serve).
`CheckOrigin` stays an exact-match allowlist (`CORS_ALLOWED_ORIGINS`).

Removed: `GET /auth/ws-token`, `LocalAuthHandler.GetWSToken`,
`auth.WSTicketService` and its Redis store, `middleware.WSTicketAuth`,
`AuthService.GenerateWSToken` / `jwt.GenerateShortLivedToken`, the gateway's
`ticket` log redaction, the web `fetchWsTicket` and ticket/token URL
parameters. No deprecation window (owner D2): web and API ship in one image
set, and a browser tab still running the old bundle keeps working, because
its upgrade carries the cookie and the server ignores the stale `?ticket=`
parameter.

Deployments: the gateway (Caddy) routes `/api/v1/ws` to the API on the UI's
origin; the all-in-one image and Helm run `server-with-ws.mjs`, which
forwards the upgrade from the UI origin to `BACKEND_API_URL` with the
client's `Cookie` and `Origin`; `next dev` rewrites it. A deployment that
sets `NEXT_PUBLIC_WS_BASE_URL` to another host must give that host the
session cookie (same site, cookie `Domain`) or, preferably, proxy the path
onto the UI origin; cross-site is not supported (D3).

### 5.2 Session binding (PR A)

Each `websocket.Client` carries an `Identity`: user, tenant, **session id**
(from the access token; empty for OIDC access tokens) and **expires at**:
`min(token exp, now + 15 min − jitter[0, 60 s])`. The handler waits until
the hub has registered the client, then:

1. re-reads the session revocation store (closes T6);
2. arms a timer that closes the socket with `4401 session expired` at
   `ExpiresAt`.

Revocation API on the hub: `RevokeSession(sid)` and
`RevokeAccess(tenant, user)`, published on Redis channel `ws:revoke`
(next to `ws:broadcast`) by `RedisBridge`; every instance applies them to its
own clients (`ApplyRevocation`), closing with `4401` and reason
`session revoked` / `access changed`. Without Redis the instance applies them
locally; when publishing fails the publishing instance still closes its own.

Hooks:

- `websocket.SessionRevocationNotifier` wraps the Redis revocation store the
  auth services already write on every session kill path (logout, sign out
  device / everywhere, password change, 2FA enrolment, user suspension,
  member suspension, session-limit eviction). It writes the store first, then
  publishes. Wired even without Redis. OIDC back-channel logout now writes it
  too (was missing).
- `PermissionVersionService` gains a change listener, called on `Increment`
  (role assigned, removed, redefined; member role changed) and `Delete`
  (member removed or suspended). It calls `RevokeAccess`.

Why close instead of re-authorizing in place: the reconnect runs the whole
upgrade chain (membership, SSO, IP allowlist) and re-subscribes, so every
subscription is re-authorized against current permissions; there is one
code path to trust. The cost is a reconnect per affected tab, spread by
client jitter.

### 5.3 Socket limits and hygiene (PR A)

| Control | Value | Before |
|---|---|---|
| Sockets per user per instance | 10, excess closed with `4429` | 10, silent close (reconnect loop) |
| Subscriptions per socket | 50 | same |
| Client messages | token bucket 10/s, burst 60 (covers re-subscribing 50 channels); excess answered `RATE_LIMITED`; 50 dropped → close `1008` | unlimited |
| Frame size | 4 KiB | same |
| Read deadline / server ping | 60 s / 54 s | same |
| Write deadline | 10 s | same |
| Close | close frame, then wait ≤ 2 s for the peer's close before dropping TCP; nothing written or processed after the close frame | `conn.Close()` at once (peer could see a reset, not the code) |
| Lifetime | ≤ 15 min (credential expiry or cap) | unbounded |
| Connection id | random 64-bit | clock-derived |

Metrics: `openctem_ws_connections` (gauge), `openctem_ws_connects_total`,
`openctem_ws_upgrade_rejections_total{reason=origin|no_identity|too_many}`,
`openctem_ws_forced_closes_total{reason=session_expired|session_revoked|access_changed|rate_limited}`,
`openctem_ws_subscribe_denied_total`, `openctem_ws_messages_throttled_total`.
Authentication and tenant-gate refusals are counted by the HTTP middleware
metrics of the route. Forced closes and revocations are logged at info with
user, tenant and session.

### 5.4 Close codes

| Code | Meaning | Client |
|---|---|---|
| `4401` | Credential no longer valid: expired, session revoked, access changed | Reconnect after jitter (0–3 s); if that upgrade fails, refresh the session (cross-tab lock) and reconnect; a failed refresh stops (the REST client handles sign-in) |
| `4429` | Too many sockets for this user | Back off at the maximum delay |
| `1008` | Message rate limit abused | Normal backoff |
| `1000` | Client-initiated | No reconnect |
| `1001`/`1006` | Server going away / network | Full-jitter backoff |

### 5.5 Web client (PR B)

- `buildWsUrl()`: same-origin `ws(s)://<host>/api/v1/ws`, no query
  credential; `NEXT_PUBLIC_WS_BASE_URL` kept as an override (§5.1).
- Full-jitter backoff (base 1 s, cap 30 s), attempt counter reset only after
  a connection stays up 30 s.
- `4401` handling as above, through the shared `refreshSession()` of the API
  client. Refreshes are serialized across tabs with the Web Locks API, and a
  tab skips its refresh when another tab refreshed in the last few seconds:
  the refresh token rotates and reuse is detected (family revocation), so N
  tabs refreshing at once would sign the user out.
- Reconnect when the active organization changes (the socket is bound to
  the tenant of the token it was opened with).

### 5.6 Edge cases

| Case | Behaviour |
|---|---|
| Organization switch with a socket open | The old socket stays bound to the old tenant (still a member, no leak); the provider reconnects on the new tenant id |
| Several tabs | Each tab has its own socket (cap 10 per user per instance); all close at the shared token's expiry; jitter + cross-tab refresh lock avoid the rotation race |
| Refresh-token rotation at reconnect | Reconnect first (the proactive refresh usually already renewed the cookie); refresh only when that fails, under the lock |
| Admin console | Separate `admin_session` cookie on `/api/v1/admin/*` (RFC-022), no socket; an admin account has no tenant, `RequireTenant` refuses it |
| All-in-one image, Helm | UI origin proxies the upgrade (`server-with-ws.mjs`), forwarding `Cookie` and `Origin`; `CORS_ALLOWED_ORIGINS` = public URL |
| Dev on another port | `next dev` rewrites `/api/v1/ws` on the UI origin; cookies ignore ports; `SECURE_COOKIES=false` for plain-HTTP dev |
| Third-party cookies blocked | Not applicable: the socket is first-party |
| Many sockets expiring together | Server lifetime jitter (60 s) + client full jitter |
| Redis down | Revocations apply on the publishing instance; other instances' sockets end at their deadline (≤ 15 min); auth middleware fails open on its revocation lookup as today |
| OIDC (Keycloak) access tokens | No session id: close at expiry and on access change only |

## 6. Rollout

| PR | Content | Depends on |
|---|---|---|
| A | This RFC; session binding (expiry, revocation store notifier, back-channel logout fix, permission-version listener, Redis `ws:revoke`, post-registration check); limits, close handshake, metrics; tests | — |
| B | Cookie-authenticated upgrade through the tenant chain, Origin required for cookie auth; delete ticket service, `/auth/ws-token`, ticket middleware, JWT-in-URL fallback; OpenAPI + web types regenerated; web client (no ticket, jitter, close codes, cross-tab refresh lock, reconnect on organization switch); docs | A |

PR A is valid on its own: tickets now carry the requesting session id and
token expiry, so ticket-opened sockets are bound too until PR B removes them.

## 7. Decisions (owner, 2026-10-03)

- **D1** Cookie authentication on the same-origin upgrade through the
  standard tenant chain, exact Origin allowlist, Origin required with the
  cookie. Accepted.
- **D2** Remove `/auth/ws-token`, the ticket service and middleware and the
  JWT-in-URL fallback completely; no deprecation window. Accepted (owner
  overrode the draft's `Deprecated()` plan).
- **D3** No ticket for cross-site deployments; serve the socket same-origin
  (gateway or proxy). Accepted.
- **D4** Bind sockets to the session: close at expiry (cap 15 min), on
  session revocation and on access change, across instances via Redis.
  Accepted.
- **D5** Close and reconnect instead of re-authorizing in place. Accepted.
- **D6** Message rate limit, close codes, close handshake, metrics as §5.3.
  Accepted.
- **D7** Stay on WebSocket (not SSE). Accepted.

## 8. Tests

- Unit (`internal/infra/websocket`): socket closes on its session's
  revocation and not another session's; access change closes the user's
  socket in that tenant only; closes at credential expiry; deadline capped
  and never unbounded; expired credential refused; revocation during the
  upgrade caught; malformed revocations close nothing; revocation reaches a
  second hub over a bus and falls back to local when the bus fails; the
  notifier records then closes (also without a store); bridge decoding;
  message flood throttled then `1008`; over the cap gets `4429`.
- Integration (`tests/integration/ws_session_binding_test.go`, Postgres +
  Redis): with two hubs on real Redis channels, the real `AuthService.Logout`,
  `TenantService.SuspendMember`, `RemoveMember` and `UpdateMemberRole` close
  a socket held on the other instance; the user's other session stays open.
- Back-channel logout records the revocation.
- Routes (PR B, DB): upgrade without a cookie 401; foreign Origin 403;
  cookie + allowed Origin connects; cookie without Origin refused; SSO-enforced
  tenant, IP allowlist and suspended member refused at upgrade; channel
  authorization unchanged.
- Web (PR B): URL has no credential; jitter bounds; `4401` → reconnect then
  refresh; `4429` → max delay; organization switch reconnects; cross-tab
  refresh lock.
