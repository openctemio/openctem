# RFC-034 — Sensor network egress: proxies per scan zone

> Status: **Proposed** (2026-10-02). Phase 0 shipped on the sensor side
> (checked 2026-10-04): `SENSOR_CONTROL_PROXY`, `SENSOR_CONTENT_PROXY`,
> `SENSOR_SCAN_PROXY` and a proxy-aware `SafeHTTPClient` that checks the
> target before the proxy (sdk-go#111, released in sdk-go v0.15.0; content
> tools follow the content proxy in sensor#102). Not built: the manifest
> `egress.control` field and Phases 1–4 (no api code yet).
> Scope: api + sdk-go + sensor (`openctemio/sensor`) + ui.
> Builds on [RFC-023](RFC-023-scan-zones-and-scanners.md) (scan zones, the three
> enforcement layers D7, the operator allow-list D8, credential tiers D12),
> [RFC-030](RFC-030-scan-work-distribution.md) (eligibility, per-host
> politeness and `limits`), [RFC-031](RFC-031-managed-sensor-updates.md)
> (content sources and refresh), [RFC-032](RFC-032-sensor-enrollment-and-identity.md)
> (key-bound identity, HPKE-sealed secrets, D5) and
> [RFC-033](RFC-033-sensor-manifest.md) (manifest, policy echo,
> `config_version`).
> Mutual distrust: [RFC-040](RFC-040-platform-sensor-mutual-distrust.md)
> §5.7 makes the operator allow-list and the egress veto one sensor-local
> policy file, and extends the forwarder's destination check from proxied
> jobs to every job of a proxy-aware tool.
>
> Problem (2026-10-02): when sensors are used for internal systems, some
> network zones can only be reached through a proxy. What is the best proxy
> solution?

## 1. Answer in short

**Put a sensor inside the segment whenever you can. Where you cannot, the
administrator attaches an *egress profile* (an ordered list of HTTP CONNECT,
HTTPS or SOCKS5 proxies) to the scan zone. The platform sends the profile to
the zone's sensors, and every scan job of that zone runs its tools through a
small forwarder inside the sensor. The forwarder holds the proxy credentials,
fails over between the proxies, and refuses any destination outside the job's
targets and the zone.**

Segmented networks are normally handled by putting a scanner in each segment
and mapping it to address ranges (§4); scanner proxies normally serve only the
scanner's own link to its console and updates, and scanning through NAT or
application proxies distorts results (§4.1). OpenCTEM
already has the first part: scan zones
route a network scan to the sensors that can reach it (RFC-023). This RFC adds
the second part: a zone whose sensors reach their targets through a proxy.

| Traffic | Today | With this RFC |
|---|---|---|
| Sensor → platform (control) | `HTTPS_PROXY`/`NO_PROXY` of the sensor's environment | Unchanged and **sensor-local only**: the sensor needs it before it can talk to the platform. An explicit `SENSOR_CONTROL_PROXY` overrides the environment for this channel alone. |
| Content downloads (templates, DBs, rules) | Upstream sources ignore the proxy (§3, G2); trivy and mirrors use the environment | Sensor-local, defaults to the control proxy, fixed for upstream sources |
| Scanner → target | Whatever each tool does with the inherited environment, unrecorded (G1) | **Platform-managed per zone** (optional per-tool override), enforced by the sensor's forwarder, recorded on every job |

Out of scope, stated in §2.1: using proxies to get around a target's rate
limits or blocks. When a target throttles or blocks a scan, the sensor backs
off and reports it. It never switches path because of the target.

## 2. Scope

**In scope.** The customer's own network. A tenant administrator configures how
a sensor reaches internal segments it cannot route to directly:

- a forward proxy that the segment's network team runs: HTTP CONNECT, HTTPS,
  or SOCKS5;
- the corporate egress proxy that a sensor must use to reach the platform and
  content sources;
- later, an SSH jump host (§6.10).

### 2.1 Non-goals

- **No rotation to evade throttling or blocking.** The design never rotates
  traffic through proxies or source addresses to get past a target's rate
  limits, WAF, IPS or blocks. Failover between the proxies of a profile
  happens only when a **proxy** fails (§6.7): its listener is down, its TLS
  handshake fails, or its health check fails. It never happens because a
  target answered 429, 403 or 503, reset the connection, or because the proxy
  reported that the target is unreachable. A throttled or blocked target makes
  the sensor back off (RFC-030 politeness, `Retry-After` honoured) and report
  `target_throttled` / `target_blocked` on the run. Profiles hold one ordered
  list of equivalent paths into one segment, chosen by the administrator.
  They are not pools for spreading load or source addresses, and the design
  has no random or round-robin selection.
  The sensor also caps how hard nuclei hits a target, whatever the platform
  asks: `SENSOR_NUCLEI_MAX_RATE_LIMIT`, `_CONCURRENCY` and `_BULK_SIZE`
  are ceilings a scan can only go below, and rate-limit flags are refused
  in extra args ([RFC-038 §6.12](RFC-038-sensor-tool-settings.md)).
- **No anonymity, no public proxy lists, no Tor.** The proxies are the
  customer's own infrastructure.
- **No VPN or overlay network.** WireGuard, IPsec or another VPN between the
  sensor and a segment are the customer's network team's choice. A sensor on
  such a network is "direct" for this RFC.
- **No raw-packet scanning through proxies.** ICMP, TCP SYN, UDP and
  traceroute cannot cross an HTTP or SOCKS5 proxy (§5.3). In a proxied zone
  these probes are refused or replaced by TCP connect probes, and the run says
  so (§6.5).
- **No WPAD.** It is never used to discover proxies: a rogue WPAD answer
  turns a sensor into a man-in-the-middle victim (§5.1).
- **No proxy for platform-shared sensors.** Platform sensors never scan
  zones (RFC-023 D14), so they never use a tenant's egress profile.

## 3. Current state (verified 2026-10-02: api `origin/develop` 5e93ef27, sdk-go `origin/main`, sensor `origin/main`)

| # | Fact | Where |
|---|---|---|
| F1 | The control channel honours `HTTP(S)_PROXY` / `NO_PROXY`: `httpsec.NewAPIClient` sets `Transport.Proxy = http.ProxyFromEnvironment` and trusts the operator-set `API_URL` (private addresses allowed, link-local, multicast and reserved refused, no redirects). The sensor's QUICK_START documents `-e HTTPS_PROXY=… -e NO_PROXY=…`. | sdk-go `pkg/httpsec/ssrf.go` `NewAPIClient`; sensor `docs/QUICK_START.md` "Through an HTTP proxy" |
| F2 | `SENSOR_CA_CERT_FILE` adds a private CA for the platform's certificate. This is the TLS-inspecting-proxy case on the control channel. Scanner processes receive `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`. | sdk-go `pkg/sensorkit/settings.go`, `pkg/core/scanner_env.go` |
| F3 | Scanner child processes get an allow-listed environment, and the allow-list includes `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` (both cases). **So the control channel's proxy is also the scanners' proxy.** | sdk-go `pkg/core/scanner_env.go` `scannerEnvAllowExact` |
| F4 | `httpsec.SafeHTTPClient` has **no** `Proxy`, so it always connects directly. It serves collectors (`core/base_collector.go`), the KEV and EPSS enrichers, and RFC-031 content fetched from default upstream sources (GitHub, the semgrep registry; sensor `internal/content/fetch.go`, `oci.go`). A configured mirror uses `NewAPIClient`, which honours the proxy. trivy downloads its own DB and honours the environment. | sdk-go `pkg/httpsec/ssrf.go`; sensor `internal/content/*.go` |
| F5 | The SDK scanner wrappers already have `Proxy` fields: nuclei (`-proxy`, `-proxy-auth`), httpx (`-proxy`), katana (`-proxy`), subfinder (`-proxy`). Nothing sets them: the sensor never passes a proxy to a tool. naabu defaults to connect scan (`-c`). | sdk-go `pkg/scanners/**/scanner.go`, `pkg/scanners/registry.go` |
| F6 | User-supplied tool flags that set a proxy (`-proxy`, `--proxy`, `-http-proxy`) are refused as dangerous. A job cannot choose its own proxy. | sensor `internal/executor/vulnscan.go` `dangerousToolFlags` |
| F7 | A scan zone is ranges plus sensors. It has no network-path attribute. The only way to reach a segment is a sensor that can route to it. | api `pkg/domain/scanzone/zone.go`, migration 000231 |
| F8 | `config_version` on the heartbeat already digests the sensor's assigned zones with each zone's last change, so a zone change reaches its sensors within one heartbeat. | api `internal/app/sensor/doorbell.go`; [sensors.md](../architecture/sensors.md#heartbeat-doorbell) |
| F9 | The sensor checks targets itself (`core.ScanTargetPolicy`: deny list, private targets only with `SENSOR_ALLOW_PRIVATE_TARGETS`). It resolves hostnames **locally**. | sdk-go `pkg/core/scan_target.go` |
| F10 | No command, result, run or activity event records how a sensor reached its targets. | api, sdk-go |

### 3.1 Gaps

- **G1. Scan traffic and control traffic share one proxy setting, and the result is unpredictable (F3).**
  - A sensor configured to reach the platform through the corporate egress
    proxy sends its tools' HTTP traffic to internal targets to that same
    proxy, unless every internal range is in `NO_PROXY`.
  - Tools that ignore the environment (naabu, nuclei's non-HTTP protocols,
    §5.3) go direct in the same job.
  - Nobody can tell afterwards which path a scan took (F10).
  - A finding produced through the corporate proxy can show the proxy's error
    page, not the target.
- **G2. Content downloads ignore the proxy on proxy-only networks (F4).** On
  a network whose only way out is the corporate proxy, the platform channel
  works but managed content from upstream sources (nuclei templates, semgrep
  rules), KEV/EPSS enrichment and collectors cannot connect. The workaround
  is an internal mirror.
- **G3. A segment reachable only through a proxy cannot be scanned (F5, F7).**
  The SDK can pass a proxy to four tools, but neither the platform nor the
  sensor has a way to configure one per zone. A host-wide `HTTPS_PROXY` would
  also capture the control channel and every other zone.
- **G4. No health or failure signal for a network path.** When a proxy is
  down, the tools time out target by target, and the run fails with many
  per-target errors instead of one clear "zone unreachable".

## 4. Network facts that shape the design

### 4.1 Constraints

- Scan engines reach segmented networks by **placement**: one scanner per
  segment, mapped to address ranges, with load-balanced groups and separate
  networks for overlapping address spaces.
- A scanner's documented proxy is for its **own link to the console and for
  updates**, configured on the scanner host or at install time, with Basic,
  Digest or NTLM authentication; endpoint agents also use system or PAC
  settings. Some appliances accept no SOCKS proxy and no TLS bridging.
- **Scanning through NAT or application proxies distorts results**: false
  positives and negatives, broken host enumeration and broken OS
  identification.
- Endpoint agents fail closed when their proxy fails: they do not try a
  direct connection.

### 4.2 Patterns extracted

1. **Segmentation is solved by placement, not by proxies.** Each segment gets
   a scanner, and the console maps scanners to address ranges. OpenCTEM's
   scan zones are this model (RFC-023), and this RFC keeps placement as the
   first recommendation.
2. **The proxy setting is per scanner, for the control and update channel.**
   It is configured on the scanner or agent host, or at install time. It is
   not pushed from the console, because the scanner needs it before it can
   reach the console.
3. **Scan traffic through a proxy is a trade-off, not a default.** It costs
   fidelity (§4.1), so a proxied zone is a deliberate choice for segments
   that offer nothing else. The design makes the reduced fidelity visible
   (§6.5) and never lets the scan path inherit the update proxy silently,
   which is what OpenCTEM does today (G1).
4. **Outbound-only scanners suit segmented networks.** A scanner that pulls
   its jobs needs only one outbound connection from the segment. OpenCTEM
   sensors already work this way (RFC-023).

## 5. Proxy kinds and tool support

### 5.1 Semantics

| Kind | What it carries | Notes for this design |
|---|---|---|
| **HTTP CONNECT** (RFC 9110 §9.3.6) | A TCP tunnel to `host:port`. The proxy then does "blind forwarding of data". | Works for any TCP protocol the proxy's port policy allows, often only 443. Credentials go in `Proxy-Authorization`. |
| **HTTP forward proxy** (absolute-form requests) | Plain HTTP requests | The proxy sees and may change the request. Used by tools for `http://` targets. |
| **HTTPS proxy** | TLS to the proxy itself, then CONNECT or a forward request | Protects the proxy credentials on the wire. Needs trust for the **proxy's** certificate (curl `--proxy-cacert`), which is the profile's `ca_bundle_pem`. |
| **SOCKS5** (RFC 1928) + username/password (RFC 1929) | CONNECT, BIND, UDP ASSOCIATE. The address may be a domain name (ATYP 3), so the proxy can resolve it. | Our tools use CONNECT only. `socks5h` (curl's name) means "the proxy resolves". With plain `socks5`, curl resolves locally. |
| **PAC** | A JavaScript `FindProxyForURL(url, host)` that returns `DIRECT` / `PROXY` / `HTTPS` / `SOCKS5` lists, tried in order | It needs a JS engine, and it chooses per URL, so the path is hard to audit. |
| **WPAD** | Discovery of a PAC through DHCP or DNS | CERT VU#598349: a device named "WPAD" can become everyone's proxy. Never used here. |
| **NO_PROXY** | No standard. curl: lowercase variables only for `http_proxy`, a leading dot matches the domain, CIDR since 7.86.0. Go: uppercase first, CIDR only for IP-literal hosts. Python `urllib`: no CIDR. wget: exact suffix, no CIDR. | A host-wide `NO_PROXY` means something different to each tool, which is G1's hidden trap. The forwarder replaces it on the scan path. |
| **Proxy authentication** | Basic, Digest, NTLM, Negotiate (Kerberos, RFC 4559). curl supports all four. | Go's transport sends only Basic (from URL userinfo) and SOCKS5 user/password. NTLM and Negotiate need a library or a local relay (O5). |
| **TLS-inspecting proxies** | The proxy re-signs server certificates with a corporate CA | Clients trust the CA (`SSL_CERT_FILE` for Go and trivy, `REQUESTS_CA_BUNDLE` for semgrep's CLI). RFC-032 §5.2 chose request signatures over mTLS because inspection breaks client certificates. |

### 5.2 Go

- **`Transport.Proxy` schemes.** `net/http` supports `http`, `https`,
  `socks5` and `socks5h`. `socks5` is treated as `socks5h`, so the proxy
  always resolves the name. `socks5h` has been accepted since Go 1.23.
  - Credentials in the proxy URL become a Basic `Proxy-Authorization` header,
    or a SOCKS5 user/password.
  - The `dns=local` option (§6.2) therefore has to be implemented by the
    forwarder: it resolves the name and sends an address.
- **`http.ProxyFromEnvironment`** (`golang.org/x/net/http/httpproxy`):
  - It reads `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, uppercase first. It
    does **not** read `ALL_PROXY`.
  - It reads the environment **once per process**.
  - It never proxies `localhost` or loopback addresses.
  - It refuses `HTTP_PROXY` under CGI (`REQUEST_METHOD` set).
  - `NO_PROXY` takes IPs, CIDRs, domains, an optional `:port` and `*`. CIDR
    rules match only IP-literal hosts.
  - Consequence: the SDK cannot switch proxies per job through the
    environment. The control client needs an explicit `Proxy` function for
    `SENSOR_CONTROL_PROXY`, and tools need their own per-process environment
    or flags.
- **`golang.org/x/net/proxy`.** It provides a SOCKS5 dialer (RFC 1928/1929)
  and `FromURL` for `socks5`/`socks5h`. It dials TCP only (no UDP
  ASSOCIATE). Other schemes can be added with `RegisterDialerType`, which is
  how the forwarder adds SSH later.
- **Not in the standard library:** NTLM, Negotiate, PAC and WPAD.
- **The SSRF guard and proxies.** When `Transport.Proxy` returns a proxy,
  `DialContext` connects to the proxy. A dial-time IP check, as in
  `httpsec.guardedTransport`, then checks the proxy's address and never the
  target's. This is why §6.8 moves the target check into the `Proxy`
  function.

### 5.3 Our tools

Verified against each tool's documentation and source at its 2026-09/10 HEAD.

| Tool | Proxy option | What goes through it | What cannot |
|---|---|---|---|
| **nuclei** | `-proxy` (list of `http`/`socks5` URLs or a file), `-proxy-internal` | It picks **one** live proxy from the list (`GetAnyAliveProxy`: failover, not rotation). HTTP proxy: HTTP, headless (Chrome `--proxy-server`) and JavaScript templates. SOCKS5: also network (TCP) templates through fastdialer, and DNS templates, by switching the resolvers to DNS over TCP. `-proxy-internal` also routes nuclei's own interactsh and reporting clients. | Out-of-band callbacks from targets to interactsh (they are the target's own egress). UDP-only probes. |
| **httpx** | `-http-proxy` / `-proxy` (http or socks) | HTTP probing | — |
| **katana** | `-proxy` (http/socks5) | Standard crawl. In headless and hybrid mode it is passed to Chrome, which adds `<-loopback>` to the bypass list. | — |
| **subfinder** | `-proxy` (http) | Only the passive sources' HTTP calls | Resolution of what it finds. It is public recon and is not routed by zones. |
| **naabu** | `-proxy` (**SOCKS5 only**), `-proxy-auth user:pass`; `-dns-order p` resolves through the proxy | TCP connect scan. "Syn Scan can't be used with socks proxy: falling back to connect scan". | SYN, UDP, ICMP host discovery |
| **trivy** | `HTTP_PROXY` / `HTTPS_PROXY`; `SSL_CERT_FILE` for inspecting proxies | Remote registries (image scans), DB, Java DB and checks downloads. Mirrors: `--db-repository`. Offline: `--skip-db-update`, `--offline-scan`. | — (fs and config scans are local) |
| **semgrep** | `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, `PROXY_USER`, `PROXY_PASSWORD` (OCaml core); `REQUESTS_CA_BUNDLE` (CLI) | Registry rule downloads, metrics, `semgrep ci` uploads. "Source code is NOT collected." | Analysis is local: no scan egress |
| **betterleaks** | No proxy flags. Its Go HTTP clients follow the environment; `git` follows `http.proxy` / `http_proxy`. | Remote sources (repos, URLs, GitHub/GitLab orgs, S3, Hugging Face) and **live credential validation** (`-v`, `-a`) over HTTP | Local scans have no egress. Live validation contacts the secret's issuer: the content/egress path, not a zone (§6.5). |
| **Raw protocols** | — | — | ICMP and raw SYN cannot be proxied. Go's SOCKS dialer and naabu do not implement UDP ASSOCIATE. |

## 6. Design

### 6.1 Three traffic classes, configured separately

| Class | Who configures it | Where it lives | Default |
|---|---|---|---|
| **Control**: sensor → platform API | The host operator | Sensor-local: `SENSOR_CONTROL_PROXY` (new; `direct` or a URL), else `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` as today. Private CA: `SENSOR_CA_CERT_FILE` (exists). | Today's behaviour |
| **Content**: templates, DBs, rules, KEV/EPSS, collectors' public sources | The host operator | Sensor-local: `SENSOR_CONTENT_PROXY` (new), else the control proxy. Mirrors stay sensor-local (RFC-031 D2). | Follows control |
| **Scan**: scanner → target | The tenant administrator | **Platform**: an egress profile per zone, optional per-tool override (§6.3); delivered with the manifest policy (§6.4) | `inherit` (today's behaviour), see O2 |

Rules:

- **The platform never sets the control path.** A setting that can cut the
  sensor off from the platform cannot be fixed remotely (§4.2 pattern 2).
- **The platform never sets a content source or content proxy.** This is
  RFC-031 D2: a compromised platform must not be able to redirect content.
- **Scan traffic stops inheriting the control proxy implicitly.** Once a
  sensor runs a job under a profile, the SDK builds the tool's environment
  from the profile:
  - it removes `HTTP(S)_PROXY`, `ALL_PROXY` and `NO_PROXY`;
  - it then sets only what the profile and the tool need (§6.5).

  Under `inherit` the environment passes through as today, so nothing changes
  for existing installations (O2).
- The sensor reports in its manifest **that** it has a control proxy and which
  kind, but not the URL or the credentials:
  `egress.control: {mode: "proxy"|"direct", scheme: "http"|"https"|"socks5", via_env: bool}`.
  The UI can then warn when a zone with private ranges is on `inherit` and the
  sensor has a control proxy, which is the G1 case.

### 6.2 Egress profiles (platform)

An **egress profile** is a reusable, tenant-owned description of one network
path. It is reusable because one segment proxy often serves several zones.

```
egress_profiles
  id, tenant_id, name (unique per tenant, case-insensitive), description,
  kind            text  -- direct | proxy   (inherit is "no profile", §6.3)
  endpoints       jsonb -- ordered list, 1..8:
                        --   [{"scheme": "http"|"https"|"socks5"|"socks5h",
                        --     "host": "proxy-a.seg.corp", "port": 3128}]
  auth            text  -- none | basic (HTTP Basic or SOCKS5 user/password, RFC 1929)
                        --   | local (credentials held on the sensor, §6.6)
  credentials_encrypted bytea  -- AES-GCM (APP_ENCRYPTION_KEY), write-only
  credential_ref  text  -- for auth=local: the name the sensor looks up
  ca_bundle_pem   text  -- trust for an https:// proxy endpoint only (§6.8)
  dns             text  -- proxy (default: hostnames sent to the proxy) | local
  health_target   text  -- host:port inside the segment that the health check reaches (§6.7)
  revision        int   -- bumped on every change; commands pin it
  created_by, created_at, updated_at
scan_zones.egress_profile_id      uuid NULL  -- NULL = inherit
scan_zone_tool_egress (tenant_id, zone_id, tool, egress_profile_id NULL, mode)
                                             -- per-tool override; mode = profile | direct | refuse
```

Validation (api, at save):

- Endpoint hosts are names or addresses. They must not be in the hard deny
  list: loopback, link-local and IMDS, multicast, reserved, unspecified. This
  is the same list as zone ranges (scan-zones.md "Range validation") and
  `httpsec`'s hard-blocked set.
- A host that is a name is resolved at save time only to give a warning, never
  to refuse: the platform often cannot resolve the customer's internal DNS.
- Ports are 1–65535.
- URLs carry no userinfo. Credentials are a separate, write-only field.
- `socks5` with `dns=proxy` is stored as `socks5h`, so what the sensor does
  is explicit.
- `https` endpoints may carry a CA bundle. `ca_bundle_pem` is ≤ 64 KiB and
  must parse as PEM certificates.
- `auth=basic` is refused when `APP_ENCRYPTION_KEY` is unset. This is the
  same rule as RFC-023 D12 T2.

API, all under `/api/v1/egress-profiles` (`GET`, `POST`, `PATCH`, `DELETE`,
plus `POST /{id}/test`, §6.7). Zones gain `egress_profile_id` and
`tool_egress` on `GET/PATCH /api/v1/scan-zones/{id}`. Responses never carry
credentials: `has_credentials: true` and `credentials_updated_at` only.
Deleting a profile that a zone uses is `409 EGRESS_PROFILE_IN_USE`.

### 6.3 Which path a job uses

Precedence for a scan command of zone Z with tool T, decided **at dispatch**
and stamped on the command:

1. `scan_zone_tool_egress (Z, T)` when present: a profile, `direct`, or
   `refuse`. `refuse` means this tool may not scan Z at all, for example SYN
   scans in a proxied zone.
2. else `scan_zones.egress_profile_id` of Z;
3. else **inherit**, today's behaviour: the sensor's environment.

Unzoned commands and commands of tools that zones do not route are not
network scans of a zone (SAST, secrets and IaC; scan-zones.md step 2). They
always use `inherit`.

The command carries a reference, never a proxy URL:

```json
"egress": { "profile_id": "…", "revision": 7, "mode": "proxy" }
```

- The sensor resolves the reference against the profiles in its policy (§6.4).
- A command whose profile or revision the sensor does not hold makes the
  sensor re-read the policy once.
- If the sensor still does not hold it, the command fails with
  `egress-profile-unknown`.

A command can therefore never point a tool at a proxy that the platform's
policy endpoint did not give this sensor. This matters until jobs are signed
(RFC-023 P3), because a tampered command could otherwise send a tool's
traffic, and any credentials in it, to a proxy that an attacker controls.

**Who gets the job.** Dispatch adds one eligibility rule to the zone claim
predicate (scan-zones.md layer 2) and to RFC-030 eligibility:

- A command with `egress.mode = proxy` is offered only to a sensor whose
  manifest declares the profile's scheme (`egress.supports`, §6.9).
- From Phase 2, the sensor must also not have reported that profile as `down`.

Older SDKs declare nothing, so they never receive proxied jobs. This fails
closed.

### 6.4 Delivery to the sensor

Profiles go out with the RFC-033 policy echo, which is already re-read when
`config_version` changes (F8). The `PUT`/`GET /api/v2/sensor/manifest` answer
gains:

```json
"policy": {
  "allowed_tools": ["nuclei", "httpx", "naabu"],
  "egress_profiles": [{
    "id": "…", "revision": 7, "name": "Plant OT segment",
    "endpoints": [{"scheme": "socks5h", "host": "198.51.100.5", "port": 1080},
                  {"scheme": "socks5h", "host": "198.51.100.6", "port": 1080}],
    "auth": "basic", "credential_ref": null,
    "ca_bundle_pem": null, "dns": "proxy",
    "health_target": "198.51.100.10:443",
    "zones": ["…zone id…"]
  }]
}
```

- The policy holds only the profiles of zones the sensor is assigned to.
- It holds **no credentials**. Platform-held credentials travel sealed in
  each command (§6.6).
- The profile's revision feeds `config_version`, so an edit reaches the sensor
  within one heartbeat.

The sensor may **veto**. The host operator sets `SENSOR_SCAN_EGRESS` to one
of:

- `platform` (default): use the profiles the platform sends;
- `direct-only`: refuse every proxied job;
- `local`: use only profiles named in a local file, `SENSOR_EGRESS_FILE`.

The sensor declares its choice in the manifest. Dispatch then stops offering
it jobs it would refuse. A command that arrives anyway fails visibly with
`egress-refused-by-host`. This keeps the RFC-023 D8 principle: the host
operator can always narrow what the platform asks for, and never silently.

### 6.5 The sensor's egress forwarder

Each tool has its own proxy support, and the support differs (§5.3). Wiring
the profile into every tool's flags would scatter the credentials, the
failover and the scope checks over a dozen code paths, and it would put the
credentials in `argv`. So the SDK runs **one forwarder per proxied job**
instead:

```
tool process ──HTTP CONNECT or SOCKS5──▶ forwarder (127.0.0.1:ephemeral, in the sensor)
                                            │  1. authenticate the tool (per-job random user/password)
                                            │  2. check the destination (below)
                                            │  3. pick the first healthy endpoint, in order
                                            ▼
                                     segment proxy  ──▶ target
```

- **Listener.** It listens on loopback only, on an ephemeral port, for the
  lifetime of one job. It accepts HTTP CONNECT, absolute-form HTTP requests,
  and SOCKS5 (no-auth refused; RFC 1929 user/password with a random per-job
  pair). Each tool gets the form it supports (§5.3).
  - Another process on the host cannot use the listener without the per-job
    password.
  - The password is in the tool's environment or arguments. It is worth
    nothing after the job.
- **Destination check.** Every connection is checked before the upstream
  dial. This is layer 3 of RFC-023 D7, now in one place for every tool:
  - an IP literal must be inside the zone's ranges ∩ the operator's local
    allow-list (D8) ∩ the job's targets, with exclusions applied;
  - a hostname must be one of the job's target hostnames, or a name under
    one when the tool crawls (katana, nuclei redirects). The operator can
    turn the crawl allowance off. The proxy resolves it (`dns=proxy`), so the
    forwarder cannot check its address; §6.8 covers that residual risk;
  - the hard deny list always applies, whatever the zone says.

  A refused destination is counted and reported on the job
  (`egress_refused: {count, sample}`). It is not an error that fails the
  scan.
- **Upstream.** The forwarder speaks HTTP CONNECT, HTTPS proxy (TLS to the
  proxy, verified against `ca_bundle_pem` or the system roots) or SOCKS5 to
  the profile's endpoints. It adds the credentials.
- **What it does not do.** It does not decrypt or inspect the tool's traffic,
  and it does not retry a tool's request. Retrying is the tool's job and is
  bounded by the tool's own flags.
- **Rate limits.** The forwarder counts connections per target host. RFC-030
  `limits` (`rate_limit`, `per_host_concurrency`) can be enforced here as a
  hard ceiling, for tools that do not apply limits themselves.

Tool wiring (the SDK builds it from the profile, not from the job's payload):

| Tool | How it reaches the forwarder | Limits in a proxied zone |
|---|---|---|
| nuclei | `-proxy socks5://u:p@127.0.0.1:port`. With a SOCKS5 proxy nuclei also proxies network (TCP) templates, and it sends DNS templates over TCP through the proxy (§5.3); an HTTP proxy would cover only HTTP, headless and JavaScript templates. `-proxy-internal` is not set, so nuclei's own update and reporting calls stay on the content path. | interactsh (OOB) is off by default in proxied zones (`-ni`): the callbacks come from targets in the segment, which normally cannot reach the interactsh server. The administrator can turn it back on per zone. |
| httpx | `-proxy http://u:p@127.0.0.1:port` | — |
| katana | `-proxy http://…` (standard mode). Headless mode passes the proxy to the browser. | Crawl scope is enforced again by the forwarder. |
| naabu | `-proxy 127.0.0.1:port -proxy-auth u:p` (SOCKS5), connect scan `-c` forced, host discovery off (`-Pn`) | SYN, UDP and ICMP are impossible (§2.1). The run shows "TCP connect through proxy; no host discovery". |
| subfinder, dnsx | Not routed by zones (public recon) | — |
| trivy (`image` against a registry in the segment) | `HTTPS_PROXY=http://u:p@127.0.0.1:port` in the child environment only | DB download stays on the content path |
| semgrep, betterleaks, trivy fs/config | Local scans: no scan egress | Rule downloads and betterleaks live secret validation (when enabled) contact public services. They use the content path, never a zone's profile. |
| Bridge sensors (Tenable/Nessus) | The bridge's link to the engine follows the bridge's `use_proxy` (RFC-023). The engine's own scan traffic is the engine's business. | — |

A tool that cannot use the profile's kind fails the command with
`egress-unsupported: <tool> cannot use <scheme> proxies`. It never falls back
to direct (O9). The manifest declares which tools support which schemes, so
dispatch normally does not offer such a job at all.

### 6.6 Secrets

Two custody options, the same as scan credentials in RFC-023 D12:

- **`auth=local` (T1, available first).** The credentials stay on the sensor
  host, in `SENSOR_EGRESS_CREDENTIALS_DIR/<credential_ref>` (a file with
  `user:password`, mode 0600) or an environment variable
  `SENSOR_EGRESS_CRED_<REF>`. The platform only names the reference. Legacy
  `rda_` sensors can use only this option.
- **`auth=basic` with platform-held credentials (T2).** They are stored with
  AES-GCM under `APP_ENCRYPTION_KEY` and are write-only through the API.
  - They are released **only to approved, key-bound (or stronger) sensors**
    (RFC-032 D5/E10).
  - They are released only in commands of the profile's zones.
  - At claim time they are sealed with HPKE to the claiming sensor's key and
    bound to the command id and expiry. This is RFC-032 §6.6, the same code
    path as scan credentials.
  - They depend on RFC-032 Phase 3. Until then T2 is refused, and the UI
    offers only `none` and `local`.

On the sensor, in both cases:

- the credentials live in the forwarder's memory only;
- tools never see them, because they authenticate to the forwarder with the
  per-job pair;
- they are never written to the outbox, the state dir or logs;
- a profile's endpoints are logged as `scheme://host:port`. `url.Redacted()`
  covers any URL that still carries userinfo.

On the platform: audit metadata records `credentials_changed: true`, never the
value. The API refuses to return them, as it does for integration credentials.

### 6.7 Health, failover and errors

**Health check (sensor).**

- **When.** While a sensor holds a profile, it checks each endpoint at most
  every 60 s while it has jobs for the profile, and every 10 min when idle. A
  manual "Test" (§6.11) triggers a check at once.
- **How.**
  1. TCP connect to the endpoint.
  2. The TLS handshake for `https` endpoints.
  3. The proxy handshake (SOCKS5 greeting and auth; for HTTP, a `CONNECT`
     with credentials).
  4. A connection through the proxy to `health_target`.
- **Result.** A failure in steps 1–3 marks the **proxy** unhealthy. A failure
  only in step 4 marks the **segment** unreachable through that proxy, which
  is reported separately: the proxy itself is up.

**Failover.**

- The forwarder tries endpoints in the administrator's order. Each new
  upstream connection takes the first endpoint whose circuit is closed.
- An endpoint's circuit **opens** after 3 consecutive proxy-level failures:
  - the proxy refuses the connection or times out;
  - the TLS handshake to the proxy fails;
  - the SOCKS5 or CONNECT handshake fails;
  - the health check fails.

  It stays open for 30 s, doubling to at most 10 min, with ±20 % jitter. One
  probe is let through when the period ends (half-open).
- **Bounded attempts.** One tool connection tries each endpoint at most once.
  With N endpoints, a connection makes at most N upstream attempts and then
  fails. The forwarder does not retry on top of that, so retries cannot
  storm.
- **What never triggers failover.** These are answers about the target, not
  failures of the proxy (§2.1):
  - `407 Proxy Authentication Required`: a configuration error, reported as
    `egress_auth_failed`;
  - a CONNECT answered `403` or `502`/`503`/`504` by the proxy for that
    target;
  - SOCKS5 replies `0x02` (not allowed), `0x03`/`0x04` (unreachable) and
    `0x05` (refused);
  - any answer from the target itself.

**Reporting.**

- **Heartbeat.** A compact `egress` member, like `content` in RFC-033 §6.12:
  `[{profile_id, revision, endpoint, state: ok|degraded|down, segment: ok|unreachable|unknown, last_error_code, checked_at, latency_ms}]`.
  The API stores the latest value per sensor.
- **Activity** (category `network`; folded and capped like every event):
  `egress_degraded`, `egress_down`, `egress_recovered`, `egress_auth_failed`.
- **Fleet health.** A sensor whose profile is `down` gets the health flag
  `egress_down`, shown with the sensor's other flags.

**Zone unreachable.**

- If every sensor of a zone reports the profile `down`, the zone's commands
  are not offered (§6.3) and wait in the zone, as they do when no zone sensor
  is online. The run carries the warning `zone "<name>" unreachable: every
  proxy of "<profile>" is down on every sensor`.
- If the run reaches its deadline (RFC-030 D10) while waiting, its batches
  fail with `ZONE_UNREACHABLE`. A zone's run fails once, with one message. It
  does not fail with one timeout per target.
- If a job is running when its proxies fail, the job fails with
  `egress-down` and the forwarder's last error. RFC-030 re-queues it within
  max attempts. There is no immediate retry.

**Targets that throttle or block (§2.1).**

- The forwarder and the SDK notice these answers from the target: HTTP 429,
  503 with `Retry-After`, repeated connection resets, and proxy CONNECT
  `403`.
- The SDK then lowers the job's rate (halving, floor 1 req/s), honours
  `Retry-After` up to 5 min, and reports `target_throttled` /
  `target_blocked` with the host on the job and the run.
- The path stays the same.

### 6.8 Safety

| Risk | Control |
|---|---|
| A proxied job escapes its zone or scope | The forwarder's destination check (§6.5) enforces zone ranges ∩ operator allow-list ∩ job targets, with exclusions applied. Platform layers 1–2 (routing, claim predicate) are unchanged. The proxy's own access list is a fourth layer. The docs give a Squid `acl dst` and a Dante `socks pass to:` example restricted to the zone's ranges, and the UI checklist recommends it. |
| `dns=proxy` lets the proxy resolve a target hostname to an address outside the zone | **Residual.** Hostnames are allowed only when they are job targets, which the platform already routed to the zone after resolving them (RFC-023 layer 1). The proxy's access list closes the remaining gap. The administrator can choose `dns=local` when the sensor can resolve the segment's names: the forwarder then resolves, checks the address against the ranges, and sends the address to the proxy. |
| A platform-supplied URL reaches a private or metadata address through a proxy (SSRF) | With a proxy, Go's `DialContext` connects to the **proxy**. The guard in `guardedTransport` would then check the proxy's address, not the target's. A proxy-aware `SafeHTTPClient` (G2 fix) therefore checks the **request URL** in its `Proxy` function: it resolves locally and refuses blocked addresses (`ValidateURL`) before it returns the proxy, and the dialer checks the proxy's address with the API-destination policy. If the target does not resolve locally, the guard refuses it (fail closed). Only fixed upstream hostnames compiled into the SDK (GitHub, the semgrep registry, the KEV/EPSS feeds) may skip local resolution, because the platform cannot choose them. |
| A tampered command sends tool traffic or credentials to an attacker's proxy | Commands carry only a profile id and revision (§6.3). Endpoints come from the authenticated policy, credentials are sealed to the claiming sensor, and the sensor operator can veto (§6.4). Signed jobs (RFC-023 P3) close the rest. |
| A malicious job sets its own proxy | Unchanged: `-proxy` and similar flags are refused in user-supplied arguments (F6), and the SDK removes the proxy variables from a proxied tool's environment. |
| A pushed template or job turns on code execution on the sensor | Custom templates arrive in a signed, command-bound manifest the sensor verifies against a pinned tenant key, code/file/headless/JS templates are refused at upload and on the sensor, and `-code`, `-file`, `-headless`, `-esc`, `-dut` and the short `-p` proxy flag are refused in extra args ([RFC-038 §6.12](RFC-038-sensor-tool-settings.md)). |
| TLS-inspecting proxy on the scan path | Not supported on the scan path. Inspection would change what the scanner sees, and its findings would describe the proxy. The CA bundle on a profile is for trusting an `https://` **proxy endpoint** only. It is never added to the tools' trust, and tools keep verifying targets as they do today. TLS-inspecting proxies on the control channel are supported through `SENSOR_CA_CERT_FILE` (F2). |
| Credential leak | §6.6: write-only, sealed per command, held in forwarder memory only, never in argv, logs or the outbox. |
| Silent changes | Every change is audited (below), changes `config_version`, and is visible on the zone. |

**Audit** (resource type `egress_profile`, severity medium; metadata is a diff
without secrets):

- `egress_profile.created`, `.updated`, `.deleted` and
  `.credentials_changed`;
- `scan_zone.egress_changed`, `scan_zone.tool_egress_changed`;
- `egress_profile.tested`: who tested, from which sensors, the result.

**Permissions.** New `sensors:egress:read`, `sensors:egress:write` and
`sensors:egress:delete`, granted to admin and owner only (O8). Assigning a
profile to a zone needs both `sensors:zones:write` and `sensors:egress:read`.

### 6.9 Manifest and protocol (RFC-033, RFC-029)

Everything on the wire is additive and feature-gated (`egress`).

- **Manifest.** The sensor declares the following, and the manifest digest
  covers it:
  ```json
  "egress": {
    "control": {"mode": "proxy", "scheme": "http", "via_env": true},
    "scan_policy": "platform",
    "supports": ["http", "https", "socks5", "socks5h"],
    "tools": {"nuclei": ["http", "socks5", "socks5h"], "naabu": ["socks5", "socks5h"]}
  }
  ```
- **Policy echo.** `egress_profiles` (§6.4).
- **Command.** `egress: {profile_id, revision, mode}`. For T2 there is also
  `egress_credentials`, an HPKE-sealed blob.
- **Heartbeat.** The `egress` health member (§6.7).
- **Job result.** The path taken is recorded in `tool.properties.egress`:
  `{mode, profile_id, revision, endpoint, refused_destinations,
  throttled_hosts}`. This is the same place as content provenance (RFC-031),
  so it reaches the stored report header for v2.

### 6.10 Later: SSH jump hosts

Some segments offer only an SSH bastion. A profile `kind=ssh` would make the
forwarder open `direct-tcpip` channels through an SSH connection
(`golang.org/x/crypto/ssh`), with the destination checks unchanged.

- The host key is pinned in the profile (no trust on first use).
- The SSH key is sealed like T2 credentials.
- `ssh -D` gives the same result, but as an external process.

This is Phase 4 and an open decision (O7). A sensor in the segment is almost
always the better answer.

### 6.11 UI

- **Settings → Sensors → Network egress** (a new tab next to Scan zones). It
  lists the profiles: name, kind, endpoints, auth (`none`, `on the sensor`,
  `stored, sealed`), the zones that use the profile, and health from each
  sensor (ok / degraded / down).
  - Create and edit form: ordered endpoints (scheme, host, port), auth,
    credentials (write-only, "replace" button), CA bundle for `https://`
    proxies, DNS (proxy / sensor), health target.
  - **Test**: chosen sensors of the profile's zones run the health check now
    (§6.7). The results appear in the dialog and in the audit log.
  - A checklist reminds the administrator to restrict the proxy itself to the
    zone's ranges, with the Squid and Dante snippets.
- **Scan zone dialog** gets a "Network path" section:
  - Direct, Through egress profile [select], or Inherit from the sensor's
    environment (with the warning from §6.1 when it applies);
  - an advanced per-tool table (profile / direct / refuse);
  - a short line on what changes in a proxied zone ("port scans: TCP connect
    only, no ping discovery; nuclei: DNS over TCP, interactsh off").
- **Zone cards and coverage** show the path as a badge: "Direct" or "via
  Plant OT segment (2 proxies)". The coverage warnings gain
  `egress_profile_down` and `private_zone_inherits_control_proxy`.
- **Sensor drawer → Network** section:
  - the control path as the sensor reported it ("proxy, http, from
    environment"; never the URL);
  - its scan-egress policy (`platform`, `direct-only` or `local`);
  - per-profile health, with the last error.
- **New scan / preview.** `POST /scan-zones/preview` returns, per zone, the
  path and the tools that will be limited or refused (`egress` member).
- **Scan run page.** Per zone and per job, the path taken (`via
  198.51.100.5:1080, SOCKS5, profile rev 7`), refused destinations, and
  throttled or blocked hosts. Run warnings explain `ZONE_UNREACHABLE`.

## 7. Compatibility

- **Nothing changes until an administrator attaches a profile.** No profile
  means `inherit`, which is today's environment pass-through, bit for bit.
- Older sensors (no `egress` feature) never receive proxied jobs (§6.3). A
  zone whose sensors are all old shows "no sensor supports this profile"
  before any scan is run.
- The control channel is unchanged. `SENSOR_CONTROL_PROXY` is optional. When
  it is unset, the environment is read as today.
- G2 fix: `SafeHTTPClient` becomes proxy-aware for the content path. It is
  safe because the URL check moves before the proxy (§6.8). Hosts without a
  proxy see no change.
- Protocol v1 sensors keep `inherit` only.

## 8. Phased plan

| Phase | Work | Repos | Effort | Risk |
|---|---|---|---|---|
| **0 — make today's behaviour explicit** | Proxy-aware `SafeHTTPClient` for the content path, with the URL check moved before the proxy (G2). `SENSOR_CONTROL_PROXY` and `SENSOR_CONTENT_PROXY`. The manifest reports `egress.control` (mode only). A doc section on proxies (control, content, the G1 trap with `NO_PROXY`). | sdk-go, sensor, docs | S | Low: additive; the guard change has unit tests for the "proxy hides the target" case |
| **1 — profiles and the forwarder** | Migration: `egress_profiles`, `scan_zones.egress_profile_id`, `scan_zone_tool_egress`. CRUD, permissions and audit. Policy echo carries profiles. Command `egress` reference. Eligibility on `egress.supports`. SDK forwarder (HTTP CONNECT and SOCKS5 upstream; `auth=none` and `local`); destination check; tool wiring for nuclei, httpx, katana, naabu and trivy image; `SENSOR_SCAN_EGRESS` veto; path recorded on results. UI: profiles tab, zone "Network path", run path. | api, sdk-go, sensor, ui | L | Medium: new data path on the sensor. It is limited to zones that opt in, and old sensors are excluded by eligibility. |
| **2 — health and failover** | Health checks, circuit breaker, heartbeat `egress` member, activity events and health flag, dispatch skips `down`, `ZONE_UNREACHABLE`, Test button, throttle/block reporting (`target_throttled`, `target_blocked`), forwarder-enforced RFC-030 `limits`. | api, sdk-go, ui | M | Medium: eligibility change; behind the `egress` feature |
| **3 — stored credentials and HTTPS proxies** | T2 credentials (needs RFC-032 Phase 3 sealing), `https://` proxy endpoints with a CA bundle, per-tool overrides in the UI, `dns=local`, path provenance on findings and assets (RFC-023 D21). | api, sdk-go, ui | M | Medium: secrets custody; reuses the RFC-032 sealing path |
| **4 — optional** | SSH jump hosts (O7). NTLM/Negotiate for the control proxy (O5). | sdk-go, sensor | M–L | Higher: new dependencies; only on demand |

## 9. Alternatives considered

| Alternative | Why not (as the default) |
|---|---|
| Rotate through proxies or source addresses when a target throttles or blocks | Out of scope by design (§2.1). It evades the target owner's controls, and our customers scan their own estate, where a block is a signal to report, not an obstacle. |
| Push `HTTPS_PROXY` to sensors from the platform | It mixes control and scan traffic (G1), can cut a sensor off from the platform, and cannot be scoped per zone or tool. |
| Wire the profile into each tool's flags, with no forwarder | Credentials in argv and in N code paths. No single destination check, so scope enforcement depends on each tool's honesty. Failover and health would be reimplemented per tool. |
| Only "put a sensor in every segment" | Still the first recommendation (§4.2). But some segments (OT, regulated enclaves, partner networks) allow only a managed proxy or bastion, and they need a proxy answer. |
| PAC files | They need a JavaScript engine in the sensor, and they choose a proxy per URL, which hides from the platform which path a job took. Explicit endpoint lists cover the scanner case. PAC remains possible for the control channel only (O6). |
| Transparent interception or a VPN client in the sensor | Network-team infrastructure, not a scanner feature. A sensor behind such a network is simply "direct". |
| SOCKS5 UDP ASSOCIATE for UDP probes | Rarely implemented by proxies and by our tools. UDP and ICMP stay "not through a proxy" (§2.1). |

## 10. Decisions

### 10.1 Technical decisions taken here

- Three traffic classes with separate settings (§6.1).
- Commands reference a profile and never carry a proxy URL (§6.3).
- A forwarder per proxied job, not per-tool proxy wiring (§6.5).
- Failover only on proxy failures, never on target answers. N endpoints mean
  at most N attempts per connection, with circuit breakers and jitter (§6.7).
- No TLS inspection on the scan path. The profile's CA bundle trusts the proxy
  endpoint only (§6.8).
- Proxied jobs are offered only to sensors that declare support (§6.3).

### 10.2 Open decisions

| # | Question | Options | Recommendation |
|---|---|---|---|
| O1 | Where do proxy settings live? | (a) platform per zone for everything; (b) sensor-local only; (c) **split**: control and content local, scan path on the platform per zone (+ per tool), host operator can veto | **(c).** The control path has to be local: the sensor needs it to reach the platform (§4.2). The scan path has to be central, so that it is per zone, audited and visible per run. The veto keeps RFC-023 D8. |
| O2 | Default for a zone with no profile | (a) `inherit`, today's behaviour; (b) `direct` (stop passing proxy variables to scanners) | **(a) now**, with the UI warning for private zones on `inherit` when a sensor has a control proxy. Revisit (b) at sensor v1.0: it fixes G1 for everyone but can break installations that scan public targets through the corporate proxy today. |
| O3 | Run proxied jobs through the in-sensor forwarder (rather than per-tool flags)? | yes / no | **Yes** (§6.5, §9): one place for scope checks, credentials and failover. |
| O4 | Platform-held proxy credentials | (a) sensor-local only; (b) also stored on the platform, HPKE-sealed to key-bound sensors | **(b) after RFC-032 Phase 3**, (a) until then. It is the same custody model as scan credentials (D5), so there is one mechanism to review. |
| O5 | Proxy authentication methods | Basic and SOCKS5 user/password; + NTLM/Negotiate (Kerberos) | **Basic and SOCKS5 user/password** for the scan path. **NTLM/Negotiate only for the control proxy, and only on demand (Phase 4)**: Go has no built-in support, and the usual workaround is a local authenticating relay (cntlm or px), which we can document. |
| O6 | PAC files and WPAD | support PAC for control; support PAC everywhere; neither | **Never WPAD. No PAC on the scan path.** PAC for the control channel only if a customer requires it (Phase 4); an explicit proxy covers the cases seen so far. |
| O7 | SSH jump host profiles | build in Phase 4 / not at all | **Phase 4, on demand.** Recommend a sensor in the segment first. |
| O8 | Who may manage egress profiles | (a) reuse `sensors:zones:write`; (b) new `sensors:egress:*`, admin and owner only | **(b).** A proxy decides where scan traffic and credentials go. This matches the rule that sensor administration is admin-only. |
| O9 | A tool that cannot use a zone's proxy (raw SYN, UDP, ICMP, DNS templates) | (a) refuse that tool or part, visibly; (b) run it direct with a warning | **(a).** Going direct would scan from a path the administrator did not choose, possibly into a segment with a different policy. |
| O10 | May the default (public) zone use a profile (the corporate egress proxy for external scans)? | yes / no | **Yes.** It is the supported way to scan the internet from a sensor whose only egress is the corporate proxy. Inspection caveats (§6.8) are shown. |

## 11. Sources

Protocols and conventions:

- RFC 9110 §9.3.6 CONNECT: https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6
- RFC 1928 SOCKS5: https://www.rfc-editor.org/rfc/rfc1928
- RFC 1929 SOCKS5 username/password: https://www.rfc-editor.org/rfc/rfc1929
- RFC 4559 HTTP Negotiate: https://www.rfc-editor.org/rfc/rfc4559
- curl SOCKS (`socks5` vs `socks5h`): https://everything.curl.dev/usingcurl/proxies/socks.html
- curl proxy environment variables: https://everything.curl.dev/usingcurl/proxies/env.html
- curl manual (proxy auth, `--proxy-cacert`): https://curl.se/docs/manpage.html
- MDN, PAC files: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file
- CERT VU#598349 (WPAD): https://www.kb.cert.org/vuls/id/598349
- GitLab, "We need to talk: can we standardize NO_PROXY?": https://about.gitlab.com/blog/we-need-to-talk-no-proxy/

Go:

- `net/http` Transport (`Proxy`, supported schemes): https://pkg.go.dev/net/http#Transport
- Go 1.10 release notes (HTTPS proxies): https://go.dev/doc/go1.10
- golang/go#24135 (`socks5h`, Go 1.23): https://github.com/golang/go/issues/24135
- `golang.org/x/net/http/httpproxy`: https://pkg.go.dev/golang.org/x/net/http/httpproxy
- `golang.org/x/net/proxy`: https://pkg.go.dev/golang.org/x/net/proxy

Tools:

- nuclei: https://github.com/projectdiscovery/nuclei (`internal/runner/proxy.go`)
- httpx: https://github.com/projectdiscovery/httpx
- katana: https://github.com/projectdiscovery/katana (`pkg/engine/hybrid/hybrid.go`)
- subfinder: https://github.com/projectdiscovery/subfinder (`pkg/subscraping/agent.go`)
- naabu: https://github.com/projectdiscovery/naabu (`pkg/runner/validate.go`)
- trivy troubleshooting (proxy, CA): https://trivy.dev/latest/docs/references/troubleshooting/
- trivy air-gapped use: https://trivy.dev/latest/docs/advanced/air-gap/
- semgrep metrics and data collection: https://docs.semgrep.dev/metrics
- betterleaks: https://github.com/betterleaks/betterleaks

OpenCTEM code read for §3: sdk-go `pkg/httpsec/ssrf.go`, `pkg/core/scanner_env.go`,
`pkg/core/scan_target.go`, `pkg/sensorkit/settings.go`, `pkg/scanners/**`;
sensor `internal/content/{fetch,oci,trivy}.go`, `internal/executor/vulnscan.go`,
`docs/QUICK_START.md`; api `pkg/domain/scanzone`, `internal/app/scan/zones.go`,
`internal/app/sensor/doorbell.go`.
