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
| Blocked ranges | Always: loopback, link-local and cloud metadata (IPv4 and IPv6), CGNAT, `0.0.0.0/8` and `::`, multicast, reserved and broadcast, IPv4-compatible and IPv4-mapped forms, and the NAT64, 6to4 and Teredo carriers that embed an IPv4 address. Private ranges (RFC 1918, ULA) unless the installation opened them (`OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`). The table agrees with the sensors' deny list (`ctis/addrscope`); the security lint fails when they drift. |
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
reason in `api/scripts/security-lint.sh`.

## Key files

- `api/pkg/httpsec/ssrf.go`: ranges, dialer, clients.
- `api/pkg/httpsec/feed_proxy.go`: the platform feed proxy (`FeedHTTPClient`).
- `api/pkg/httpsec/bypass_test.go`: the bypass suite (address spellings, host
  spellings, schemes, redirects, proxy environment, error text).
- `api/internal/infra/fetchers/git_snapshot.go`: rule-source fetches.
- `api/scripts/security-lint.sh`: the CI rules that keep every outbound client
  on the guard.
