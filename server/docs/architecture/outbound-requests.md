# Outbound requests

Many features make the API connect to an address that someone other than the
operator chose: an organization's webhook, Slack, Teams or Telegram channel,
Splunk collector, Jira or GitLab server, SMTP relay, S3 bucket, OpenID Connect
provider, AI endpoint or rule-source repository, and the documents a sign-in or
an MCP client names. Each of these is a way to make the platform's network
position act for the caller. This page describes the one guard every such
connection goes through.

## Threat model

- **Who chooses the destination:** an organization member with the right
  permission (integrations, settings), a platform administrator, a CI provider
  through its OpenID Connect issuer, or data the platform reads (DNS records,
  documents fetched from a URL).
- **What they want:** the cloud metadata service (instance credentials), the
  platform's own services (database, Redis, the sensor gateway, the signer),
  other services on the operator's network, or another organization's private
  services on a shared instance; a port scan of any of them; or a slow
  destination that ties up workers.
- **What the guard guarantees:** a connection is made only to an address that
  passed the policy, decided on the address the connection actually uses.

## The guard (`pkg/httpsec`)

| Rule | How |
|---|---|
| Decision at dial time | The dialer resolves the host once, checks every answer, and connects to a checked address itself. It never hands the host name to the system dialer, so a second DNS answer (rebinding, TTL 0) cannot change the destination. Every connection is checked, including each redirect hop and every new connection of a pooled client. |
| Blocked ranges | Always: loopback, link-local and cloud metadata (IPv4 and IPv6), CGNAT, `0.0.0.0/8` and `::`, multicast, reserved and broadcast, IPv4-compatible and IPv4-mapped forms, and the NAT64, 6to4 and Teredo carriers that embed an IPv4 address. Private ranges (RFC 1918, ULA) unless the installation opened them ("Private network destinations" below). The table agrees with the sensors' deny list (`ctis/addrscope`); the security lint fails when they drift. |
| Blocked names | `localhost` and the metadata aliases, in any case and with a trailing dot, before any lookup. |
| Schemes | http and https only. Rule sources: https only, and go-git has no ssh, `git://` or `file://` transport registered. |
| Proxies | No guarded client takes a proxy from the environment (`HTTP_PROXY`, `HTTPS_PROXY`): the check would then vet the proxy instead of the destination. The one exception is the opt-in platform feed proxy below, used by `FeedHTTPClient` only. |
| Redirects | Each hop is dialed through the guard again. The default policy also refuses https to http and stops after 5 hops. Clients that carry a credential either refuse redirects or follow only https hops through the guard (Jira, DefectDojo). |
| Errors | A refusal says only that the destination is blocked (`ErrBlockedDestination`); a lookup failure says only that the host does not resolve (`ErrUnresolvable`). Neither names the resolved address or the platform's resolver, so a probe of chosen host names cannot map the internal network. |
| Bodies | Responses are read through `httpsec.ReadLimited` or `httpsec.DecodeJSON` with a cap, and an upstream body is never copied into an error (security lint rules 8 and 9). |

Clients:

- `SafeHTTPClient`: public addresses and the ranges the installation opened.
- `RequestPolicyHTTPClient`: the private-range decision is taken per connection
  from the request context (`WithInstancePrivate`), for features that allow
  private hosts per organization (rule sources); no connection reuse across
  requests.
- `PrivateAllowedHTTPClient`: every private range, for a destination a platform
  administrator set (the platform AI endpoint). Never for an organization's
  value.
- `SafeDialContext` and `ResolveSafeHost`: the same checks for transports that
  are not plain HTTP (SMTP, a custom TLS client).

## Private network destinations

A self-managed install often has its GitLab, Jira or mail relay on a private
address. Private ranges are opened in two places, and the guard allows the
union of both:

| Source | Where | Applied |
|---|---|---|
| Set on the server | `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` | at start-up; a change needs a restart |
| Opened in the console | console System > Private networks (platform setting `network.private_destinations`) | at once on the server that saved it, within 15 seconds on the others |

- The guard reads one immutable snapshot of the policy (an atomic pointer) on
  every check, and the dialer checks every connection again at connect time,
  so a change applies from the next connection and a check never mixes two
  lists. When a change closes a range, the idle keep-alive connections of
  every client built by `pkg/httpsec` are closed, so none is reused into the
  closed range; requests in flight finish. A transport built elsewhere around
  `SafeDialContext` keeps its idle connections until they time out. Each
  server reloads the stored list every 15 seconds
  (`privatedestinations.Service.Start`); a refresh that read the list before a
  save on the same server does not apply its older copy over the save. A
  database error keeps the list in force, and a stored list that no longer
  passes the checks opens nothing.
- Console rules: at most 32 ranges, each inside `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7`; an IPv6 range must be
  `/48` or narrower (one site); a range inside a never-reachable range (the
  IPv6 cloud metadata addresses) is refused. The widest IPv4 range is a whole
  private block (`10.0.0.0/8`); the console asks for a second look at
  anything wider than `/24` (IPv4) or `/64` (IPv6). Each range may carry a
  note (plain text, one line, at most 100 characters).
- Never reachable, whatever either source says: loopback, link-local and
  cloud metadata, CGNAT and the other ranges in the table above. They are
  checked before the opened ranges.
- With `SIGNUP_MODE=open` (anyone may create an organization) the console
  opens no range: a change that lists one answers 409
  `PRIVATE_RANGE_OPEN_SIGNUP` and a stored list is not applied, the same rule
  that refuses `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` at start-up.
- `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` (every private range) stays a
  development-only switch: the API refuses to start with it in any other
  `APP_ENV`.

Who may change it. An opened range is reachable by every organization's
webhooks, integrations and CI connections, so the change is the platform
owner's: permission `platform.settings.network` (granted to the platform owner
role only), a fresh step-up code and a reason. The change is a critical
admin audit row with the previous and new lists (`previous_ranges`,
`ranges`, and the server's ranges for context), and every administrator is
told. Tenant sessions never reach the console API; a console role without
the permission reads the list but cannot change it.

Test a destination. `POST /api/v1/admin/settings/private-destinations/test`
with `{"host": "gitlab.example.com"}` resolves the name (or reads an IP
literal) and reports each address: `allowed` (public), `allowed_private`
(which range opens it and whether it is set on the server or in the
console), `blocked_private` (the `/24` or `/64` that would open it) or
`hard_blocked` (why: loopback, link-local, cloud metadata, ...). It only
resolves: it never connects to the host. It takes the same permission as a
change and is limited to 10 tests a minute per administrator.

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/admin/settings/private-destinations` | `platform.settings.read` (any administrator) |
| PUT | `/api/v1/admin/settings/private-destinations` | `platform.settings.network` + fresh step-up + reason |
| POST | `/api/v1/admin/settings/private-destinations/test` | `platform.settings.network`, rate limited |

## Platform feed proxy

An installation inside a corporate network often reaches the internet only
through an HTTPS proxy. `OPENCTEM_HTTPSEC_FEED_PROXY` (and
`OPENCTEM_HTTPSEC_FEED_NO_PROXY` for hosts reached directly) routes the
platform's own feed fetchers through it: vulnerability bundles, CISA KEV,
EPSS, the CTEM-ID catalog, the public program feed and the release feed.
They use `httpsec.FeedHTTPClient`; without the setting it is
`SafeHTTPClient`.

| Rule | Why |
|---|---|
| Only `FeedHTTPClient` uses the proxy; every client that can reach a URL an organization supplies keeps dialing directly through the guard | the destination check would otherwise be done by the proxy's network, not ours |
| The destination is checked before the request is handed to the proxy: dangerous names, blocked address literals and names whose local answers fall in a blocked range are refused; a name the local resolver cannot answer is left to the proxy | a network whose only exit is a proxy usually has no outside DNS; the feed URLs are fixed or set by the operator, never by an organization |
| Only https destinations are proxied (CONNECT); plain http and loopback names take the guarded direct dial | TLS stays end to end, so the certificate is still verified against the destination's name and the proxy cannot read or change the feed |
| The proxy may be on a private address; loopback, link-local and metadata addresses are refused | it is the operator's own setting; the hard-blocked ranges are never reachable |
| A malformed value stops the start; the password is never logged (start-up log shows host:port, logged URLs lose their userinfo) | a silently ignored setting is debugged for hours; credentials stay out of logs |
| Signatures do not change: bundles are verified against the pinned root key whatever path delivered them | the proxy is a transport, never a trust anchor |

## Destinations that do not go through it

Only addresses the operator sets in the server's environment: the audit-log
sink, the sensor transport probe, the scan-zone resolver, the signer socket, the
operator's own S3 storage and the internal relay. Each is listed with its
reason in `server/scripts/security-lint.sh`.

## Key files

- `server/pkg/httpsec/ssrf.go`: ranges, dialer, clients.
- `server/pkg/httpsec/private_policy.go`: the private-range snapshot, console
  range checks and the resolve-only destination test.
- `server/internal/app/privatedestinations/`: the console setting (store,
  audit, refresh on every server).
- `server/pkg/httpsec/feed_proxy.go`: the platform feed proxy (`FeedHTTPClient`).
- `server/pkg/httpsec/bypass_test.go`: the bypass suite (address spellings, host
  spellings, schemes, redirects, proxy environment, error text).
- `server/internal/infra/fetchers/git_snapshot.go`: rule-source fetches.
- `server/scripts/security-lint.sh`: the CI rules that keep every outbound client
  on the guard.
