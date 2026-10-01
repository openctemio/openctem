# RFC-023 — Scan zones and the Scanners resource

> Status: **Proposed** (2026-10-01)
> Scope: api + agent + ui (+ sdk-go for job verification).
> OpenCTEM is an open platform: anyone can build tools, agents, connectors and
> collectors with the SDK and push results in. Zones and every security control
> here are therefore defined at the **protocol** level and implemented once in
> the **SDK**, so third-party sensors get them by default (§4).
>
> Lets a tenant admin register the scanners that serve their organization, group
> their networks into **scan zones** (address ranges → the scanners that may
> scan them), and have every scan routed to, and enforced by, the right scanner.
> Modeled on Tenable Security Center's Nessus Scanners + Scan Zones, adapted for
> a multi-tenant product and hardened beyond it.

## 1. Problem

A tenant with segmented networks (e.g. `10.230.0.0/16`, `10.1.0.0/16`,
`10.210.0.0/16`, each reachable only from a scanner inside it) cannot express
"scans of 10.230.x run on the scanner in that network", and nothing stops any
scanner from scanning any address. The 2026-10-01 code review found:

1. **No zone, site or allowed-range concept** anywhere. A scan command carries
   no agent; any agent of the tenant may claim it. The poll matches only
   `required_capabilities` (`command_repository.go:117-148`); tool, tags and
   `routing_tags` are stored but never matched.
2. **Only the first target of a scan is dispatched**: `payload.target =
   sc.Targets[0]` (`scan/trigger.go:422`). A 10-address scan scans one.
3. **Private targets are refused at scan creation**
   (`WithAllowInternalIPs(false)`, `scan/crud.go:217`), so on-prem scanning only
   works through asset groups.
4. **Auto mode falls back to platform agents** when no tenant agent is free,
   without checking permission or target type (`scan/trigger.go:648-662`). In
   SaaS this would send a tenant's internal targets to shared infrastructure.
5. **Scope exclusions are fail-open** and applied only to asset-group scans;
   the agent ignores `excluded_asset_ids`.
6. **Agents trust any well-formed job over TLS**: commands are not signed, and
   the agent has no allowed-range guard (only a global
   `AGENT_ALLOW_PRIVATE_TARGETS`). A compromised control plane, or an attacker
   on the path, decides what every scanner scans. Also: `::/128` is not blocked,
   recon `extra_args` can add targets (`-u/-l/-host/-d`), hostnames are resolved
   without pinning (DNS rebinding).
7. **Agent keys never expire by default** (0 of 73 live agents have an
   expiry); key scopes are stored but not enforced.
8. **Tenable coverage jobs are unroutable**: dispatched with capability `infra`,
   which the agent never advertises.
9. **Overlapping private space within one tenant collapses**: assets are unique
   on `(tenant_id, name)`, so `10.0.0.5` at two sites is one asset.

## 2. What we learn from the field

| | Tenable SC | Tenable VM | Rapid7 InsightVM | Qualys | runZero |
|---|---|---|---|---|---|
| Link direction | SC→scanner :8834 (managed) or scanner→SC :8837 (linked) | Scanner→cloud, linking key | Either; reverse uses 60-min secret | Appliance→cloud :443, polls 190 s | Explorer→cloud, stamped token |
| Routing | Scan zones (ranges→scanners), narrowest first, least busy | Scanner groups with routing targets, narrowest match | Site → engine/pool | Asset group → appliances | Site → explorers |
| Out-of-zone target | Enforced for linked; **ignored when one zone is selected** | **Skipped, partial results + warning** | Site-scoped | Group-scoped | Must be in task scope |
| Overlapping IP | Distribution across zones | "Networks" stamped on assets | Site-scoped correlation | "Networks" | Sites |
| Credentials | In SC, or CyberArk/Vault | Cloud or PAM | Console or CyberArk | **Appliance pulls from vault** | Sent only if task CIDR matches |
| Health | 16-flag status incl. fingerprint mismatch | Linked/online | Connection status | 4-h heartbeat | Online + approval |

Threat evidence that shapes the design: scanners are high-value pivots (stolen
scan credentials from compromised targets; a tampered target list redirecting
credentials to an attacker — Praetorian 2025); unauthenticated update channels
(Rapid7 CVE-2022-4261/3913); local privilege escalation in scanner agents
(Nessus Agent CVE-2024-3291/3292).

## 3. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **One "Scanners" resource** over everything that executes scans for a tenant: OpenCTEM agents (in-network, outbound-only) and external engines (Nessus Pro, Tenable.sc; OpenVAS/Qualys later) reached through a bridge agent. | Today they live on two pages with two status models. Tenable/Qualys show one list. |
| D2 | **Outbound-only.** Our scanners always connect out and long-poll; the control plane never opens a connection into a tenant network. External engines are reached by an agent in their zone ("bridge"). A direct control-plane→engine connection is allowed only for internet-reachable/cloud engines. | No inbound path into customer networks; matches Qualys/runZero/Tenable-linked; already decided for RFC-007. |
| D3 | **Scan zone** = tenant-owned: name, network, address ranges (IP, CIDR, IP ranges), assigned scanners, optional description. Overlapping zones are allowed for redundancy. | The routing primitive every vendor converges on. |
| D4 | **Routing: narrowest matching zone, then least-busy scanner with capacity**; targets are materialised and batched server-side (`TargetsPerJob`). | Tenable's algorithm; fixes the Targets[0] bug at the root. |
| D5 | **Out-of-zone targets are skipped with an explicit warning on the run, never sent to "any scanner".** Unlike SC, a selected zone's ranges are **always** enforced. | Fail closed; SC's single-zone bypass is a known pitfall. |
| D6 | **Zones are opt-in per tenant.** With no zones, behavior stays as today for public targets. Once a tenant defines a zone, private (RFC 1918 / ULA) targets **require** a zone; public targets and domains use the tenant's **Default zone** (internet-facing scanners). | No surprise breakage; private scanning becomes possible exactly where it is safe. |
| D7 | **Three independent enforcement layers.** (1) Dispatch pins the job to a zone scanner. (2) The claim query refuses a job whose targets are outside the polling scanner's zones. (3) **The scanner itself refuses** targets outside its allowed ranges, checked on resolved IPs with the resolved IP pinned for the scan. | Each layer survives the failure of the one before; layer 3 survives a compromised control plane only if its ranges do not come solely from that control plane (D8). |
| D8 | **Scanner allow-list = intersection of (a) zone ranges from a signed job manifest and (b) an optional operator-set local list** (`--allowed-ranges`, like Nessus `nessusd.rules`). The UI shows (b) as "locked by operator". Built-in deny always applies: loopback, link-local/IMDS, `::/128`, multicast, the control plane's own address. | (a) stops path attackers; only (b) stops a fully compromised control plane. Recommended for high-security sites. |
| D9 | **Signed jobs (Ed25519).** The control plane signs tenant, scanner id, command id, targets, tool, args digest, zone ranges, expiry and nonce, with a signing key held outside the database (KMS / mounted secret). The agent pins the public key at enrollment and checks signature, expiry, replay and allow-list before running. Agent updates/templates follow the same rule. | Turns "anyone who can write the commands table or MITM the link" into "needs the signing key". |
| D10 | **Enrollment:** single-use token valid ≤60 min, bound to the tenant and optionally a zone → per-scanner key with **default 90-day TTL and auto-renew** (RFC-014 machinery, now on by default); **new scanners are "pending approval"** and get no jobs until a tenant admin approves; revoke takes effect on the next poll. | Rapid7 60-min secret, runZero approve-to-trust; closes "keys never expire". |
| D11 | **Fixed capability set.** Scanners run typed scan jobs only: no shell, tunnel or free-form command. `extra_args` are allow-listed per tool; target-bearing flags are rejected. | Removes the pivot surface (runZero model). |
| D12 | **Credential custody tiers.** T1 (default): secrets stay on the scanner/bridge or are pulled by it from the tenant's vault; the control plane never holds them. T2 (opt-in): stored encrypted in the control plane (refused when `APP_ENCRYPTION_KEY` is unset), envelope-encrypted per job to the scanner's key, and **released only when the job's targets lie inside the credential's scope ranges**. | Qualys vault pull + runZero scoped release; matches the RFC-007 trust decision. |
| D13 | **Health as flags**, not one word: online, busy (+ free capacity), version / upgrade required, auth error, certificate mismatch, fingerprint mismatch (engine UUID changed), plugins/templates out of sync, disabled, pending approval, quarantined. "Update status" runs an on-demand probe. A scanner silent past N heartbeats, or whose fingerprint changed, is quarantined automatically. | SC's 16-flag status is what operators rely on; quarantine is the safe default. |
| D14 | **Platform layer** (RFC-022 console): shared scanners and zones offered to tenants. They may scan **public** targets only, never receive tenant credentials, and are always labelled "shared". The silent auto-fallback to platform agents is removed: using them is an explicit per-scan or per-tenant choice. | Matches SC's admin-assigned zones without leaking internal targets. |
| D15 | **Networks for overlapping space** (later phase): every zone belongs to a network (one default network per tenant); asset identity becomes `(tenant, network, address)` for network addresses, and results are stamped with the scanner's network. | Tenable VM / Qualys "networks", runZero "sites"; required for multi-site customers reusing 10/8. |
| D16 | **Permissions:** `scanners:read/write/delete`, `zones:read/write/delete`, `scanners:approve` (tenant owner/admin by default; members read-only). All zone, scanner, approval, key and credential-release events are audited. | Least privilege; a new permission is added in Go, the seed migration and the UI constants together (authorization-matrix rules). |
| D17 | **Scope stays separate from zones.** Scope = *may* we scan this; zone = *who can reach* it. Exclusions are enforced at dispatch for **every** path and fail closed; an optional tenant setting requires targets to be in scope. | Two questions, one CIDR matcher (`pkg/domain/scope`). |

## 4. Extensibility: sensors built with the SDK

The platform is designed so that third parties write their own tools, agents,
connectors and collectors with `sdk-go` (`core.Scanner`, `core.Collector`,
`core.Connector`/`Provider`, `core.Parser`, `core.Agent`, `Pusher`, the
`platform` poller) and push data in. Zones must not depend on *our* agent
behaving well, so:

| # | Decision | Why |
|---|---|---|
| D18 | **"Sensor" is the umbrella term** (Tenable VM *Settings → Sensors*, Qualys *Sensors*): software running on the customer side that authenticates **to** the platform with its own key and heartbeat. Sensors are classified by **operational role**, as Tenable separates scanners from agents: **Scanner** — network vantage point that assesses *other* hosts, routed by **scan zone** (our in-network runtime in scan mode; external engines such as Nessus/Tenable.sc/OpenVAS behind a scanner acting as bridge). **Agent** — installed on an endpoint, reports only about *its own* host (inventory, local vulnerabilities, telemetry), grouped by **agent group**, never receives network targets. **Collector** — pushes data from systems inside the customer network (SIEM forwarder, CMDB), never receives targets. **Network monitor** — passive (later). **Integration** stays the term for external systems the *platform* calls with credentials (Jira, Slack, Splunk out, GitHub, Wiz API) or that call in via webhook; no software of ours runs for them. Rule: *who runs the code and who holds the identity.* | Today's "Agent" is a Tenable-style **scanner**; keeping that name would mislead anyone who knows Tenable. One registry, approval, key and health model for every role, first- or third-party. |
| D18a | **Roles are capabilities, approved separately.** One runtime built with the SDK may hold several roles (e.g. scanner + collector). Each role is declared, approved and audited on its own and carries its own rules: only the *scanner* role receives network targets and is zone-checked; the *agent* role is bound to its own host identity; the *collector* role can only push its declared data kinds. In the SDK, `core.Scanner` / `core.Collector` / `core.Connector` map to these roles and `core.Agent` is documented as the **sensor runtime** that hosts them. | Flexible for SDK authors without letting one role borrow another's powers. |
| D18b | **Migration without breakage.** API paths and tables keep the name `agents` (plus a `role` column); every existing agent becomes a **scanner** (what they do today). UI and docs move to the new terms; `/agents` redirects to *Settings → Sensors*. Tabs: **Scanners · Agents · Collectors · Scan zones · Networks**, one "Add sensor" flow (one-time enrollment token → approval). Supersedes the 2026-08 naming decision ("Agent" as the umbrella runtime term). | Correct vocabulary for users, zero API churn for SDK consumers. |
| D19 | **The rules are protocol, the code is SDK.** Signature/expiry/replay checks, the allow-list on resolved IPs with pinning, the built-in deny list and per-target skip reporting live in `sdk-go` (`platform` poller + a guarded resolver/dialer handed to scanners). A tool implementing `core.Scanner` is only ever called with targets that already passed the guard, and gets a pinned address to use. Our agent is just one consumer of the SDK. | Third-party runners inherit the controls without writing them; one audited implementation. |
| D20 | **Capability negotiation.** At enrollment and on every heartbeat a sensor declares: protocol version, SDK version, **features** (`signed_jobs`, `zone_guard`, `ip_pinning`) and a **tool manifest** per tool (target kinds accepted: ip/cidr/domain/url/repo/image/cloud; whether it needs network reach; output types; credential needs). The server routes by manifest: zone routing applies only to network-reaching tools (a repo SAST tool needs no zone). **Jobs with private network targets are dispatched only to sensors that advertise `signed_jobs` + `zone_guard`**, unless the tenant explicitly allows legacy sensors (shown as a warning). | Safe by default for unknown code; non-network tools are unaffected. |
| D21 | **Push is authorized, not just authenticated.** A sensor key's scopes (stored today, enforced from now) limit: the data kinds it may write (findings, assets, telemetry, …); the **tool names it may report as** (a collector must not report as `nessus` and auto-resolve real Nessus findings, since auto-resolve is scoped by tool); and, for zone-bound runners, the addresses it may report on (results outside its zones are quarantined for review, not ingested). Every record is stamped with sensor id, kind and zone (provenance). | Closes forged-result and cross-network write paths that any SDK user could otherwise reach. |
| D22 | **Trust tiers.** *First-party* (our signed builds), *verified* (passes the SDK conformance suite, signed release), *custom* (tenant-built, approved by a tenant admin). Custom sensors never receive control-plane-held credentials (T2) and their findings are labelled as such; platform-shared scanners are first-party only. | Openness without granting unknown code the most sensitive powers. |
| D23 | **Conformance suite in the SDK** (`platform/conformance`): a fake control plane that proves a sensor rejects unsigned, expired, replayed and out-of-range jobs, never dials the deny list, reports skips, and honours revocation. Required for *verified*. | Makes "secure by default" checkable by third parties and in our CI. |
| D24 | **Versioned protocol.** The server publishes a minimum protocol version and a deprecation window; sensors below it keep pushing (collectors) but receive no new jobs; the UI flags "upgrade required". | Lets the platform evolve security requirements without breaking the ecosystem overnight. |

## 4b. Protocol v2: identity, integrity and supply chain

Target model for every sensor (first- or third-party), chosen to be the most
secure option that still works through corporate proxies and for third-party
developers. Sources: GitHub Actions runner auth, Kubernetes kubelet TLS
bootstrapping, Tenable sensor linking, Elastic Fleet message signing, Datadog
Remote Config (TUF), Nuclei template signing (and its CVE-2024-43405 bypass),
RFC 9421 / 9449 / 9530 / 8705, OWASP API Top 10 2023, NIST SP 800-204/207,
CISA Secure by Design.

| # | Decision |
|---|---|
| P1 | **No bearer secret on the wire after enrollment.** Enrollment uses a single-use token (≤60 min, hashed at rest, bound to tenant + role, optionally zone). The sensor generates an **Ed25519 key pair locally** (private key never leaves the host; file mode 0600, or the OS keystore/TPM when available) and registers only the public key. Today's `rda_` keys become v1-only. |
| P2 | **Every request is signed** with HTTP Message Signatures (**RFC 9421**) over method, target URI, **Content-Digest (RFC 9530)**, `created` and a nonce, keyed by the sensor id. The server allows ±5 min clock skew and rejects replayed nonces. Unlike mTLS this survives TLS-terminating proxies and load balancers, and a captured request or log line cannot be replayed or reused. |
| P3 | **Optional mTLS mode** for self-hosted, high-assurance deployments: kubelet-style CSR enrollment, client certificates of ≤24 h renewed at half-life, and a SPIFFE federation hook for organisations already running SPIRE. |
| P4 | **Automatic key rotation and instant revocation.** The sensor rotates its key every 30 days (the new public key is submitted signed by the old one); revocation and quarantine are checked on every request, not at connect. |
| P5 | **Jobs are JWS (EdDSA) envelopes** carrying tenant, sensor id, command id, targets, tool, args digest, zone ranges, `iat`/`exp`, nonce and key id. The SDK verifies before parsing anything else and **executes exactly the verified bytes** (the Nuclei CVE-2024-43405 lesson: never verify one representation and run another). |
| P6 | **Signing keys rotate without re-enrolling the fleet** (avoids Elastic Fleet's forced re-enrolment): an offline **root key** signs a published key set of online job-signing keys with expiries (TUF-style roles); the sensor pins the root public key at enrollment and refreshes the key set on heartbeat. |
| P7 | **Content and updates are signed too:** scan templates and checks (code-type templates must be signed), tool bundles and sensor self-updates are delivered with TUF metadata (expiry, rollback and freeze protection). |
| P8 | **Supply chain for every release** of the SDK, the agent and the images: keyless **Sigstore cosign** signatures, **SLSA Build L3** provenance, a CycloneDX **SBOM**, `-trimpath` reproducible builds, `govulncheck` + `gosec` + lint gates; installers verify signatures before running anything. |
| P9 | **Push integrity:** the signed request covers the body digest; each report carries an `Idempotency-Key` (retries never duplicate); strict schema validation with size, depth and decompression limits; per-sensor quotas and rate limits; provenance stamped **by the server**; anomalous pushes (volume spikes, out-of-zone or out-of-job assets) are quarantined for review instead of merged. |
| P10 | **Transport:** TLS 1.3 preferred with 1.2 as the floor, and the hybrid post-quantum key exchange (X25519MLKEM768) that Go's `crypto/tls` already negotiates by default; operator-supplied CA bundle pinning (no hard-coded leaf pins, which break inspecting proxies); `InsecureSkipVerify` impossible without an explicit dev flag; redirects never carry credentials across origins or downgrade to HTTP; HTTPS long-poll kept (proxy- and firewall-friendly), with HTTP/2. |
| P11 | **Crypto agility:** every envelope and key carries an algorithm id, so signatures can move to post-quantum ML-DSA later without a protocol break. |
| P12 | **Tamper-evident audit** of enrollment, approval, key rotation and revocation, job signing, credential release and quarantine, in the hash-chained audit log (whose current chain-break bug is fixed first). |
| P13 | **SDK secure defaults are not optional:** the SDK's HTTP client, resolver guard, verification and bounded readers are on by default and cannot be silently weakened; a conformance suite (D23) proves it for third-party sensors. |

**v1 during the transition.** v1 sensors (static `rda_` key, unsigned jobs)
keep working (§9), but receive compensating server-side controls: zone routing
and the claim predicate (layers 1–2), push scopes, quotas and quarantine,
default key expiry, and "legacy" labelling. Private-network jobs go to v1
scanners only where the tenant has allowed legacy scanners. Raising the minimum
protocol (C7) then retires v1 on the operator's schedule.

## 5. Data model (Phase 1–2)

```
scan_networks   id, tenant_id, name, is_default                      (Phase 4 uses it for identity)
scan_zones      id, tenant_id, network_id, name, description, is_default,
                ranges inet/cidr[] (validated, normalised, no /0 for private),
                created_by, created_at, updated_at
scan_zone_scanners  zone_id, agent_id   (PK both; same-tenant enforced in SQL)
agents          (the sensor registry) + role (scanner|agent|collector|monitor; a
                runtime may hold several roles), + bridge_engine (for scanners fronting an engine),
                + approval_state (pending|approved|rejected), + trust_tier,
                + protocol_version, sdk_version, features text[], tool_manifest jsonb,
                + health_flags int, + allowed_ranges_local cidr[] (reported, read-only in UI)
agent_api_keys  scopes enforced: ingest kinds, reportable tool names
scanner_engines id, tenant_id, kind (nessus_pro|tenable_sc|openvas…), name, host, port,
                verify_tls, ca_pin/fingerprint, use_proxy, bridge_agent_id,
                credential_tier (agent_local|vault|control_plane), credential_ref,
                health_flags, engine_uuid, version, last_status_at
```

Routing and claim queries use a single CIDR matcher (reuse
`pkg/domain/scope` matching). All tables carry `tenant_id` and every query is
tenant-scoped.

## 6. Flow

1. **Create scan**: targets validated; private targets accepted when the tenant
   has a zone covering them (D6). Exclusions removed (fail closed).
2. **Trigger**: materialise targets (expand asset groups server-side), group by
   narrowest zone, batch by `TargetsPerJob`, pick the least-busy approved
   scanner in the zone, create one signed command per batch pinned to it.
   Uncovered targets are listed in the run's warnings.
3. **Poll/claim**: the query returns only commands pinned to the caller, or
   unpinned ones whose targets lie in the caller's zones and whose tool the
   caller has (layer 2).
4. **Execute**: the agent verifies signature, expiry and replay, intersects the
   manifest ranges with its local list, resolves hostnames, rejects any resolved
   IP outside the allow-list or in the built-in deny list, pins the IP, runs the
   typed tool (layer 3), and reports per-target skips.
5. **Results**: ingest as today; results stamped with zone (and network, Phase 4).

## 7. UI (tenant admin)

**Settings → Scanning resources**, in the shape of SC's "Nessus Scanners" page:

- **Scanners** tab: one table of agents and engines — name, type, capabilities,
  status (flag pills: Working, Pending approval, Auth error, …), host, version,
  zones, uptime, last seen. Actions: **Add** (agent: one-time enrollment command;
  engine: form with name, description, host, port 8834, enabled, verify TLS,
  proxy, authentication with custody tier, zones, bridge agent), **Update
  status**, **Approve**, **Revoke**, **Rotate key**.
- **Scan zones** tab: name, ranges, scanners, coverage of assets (how many
  inventory addresses fall in no zone), and warnings for private ranges without
  a scanner.
- **New scan**: a zone picker (Automatic by default), and a preview of which
  targets go to which scanner and which are skipped.

## 8. Phases

| Phase | Content | Ships |
|---|---|---|
| **0 — Fix what is broken today** (no new concepts) | All targets dispatched, batched by `TargetsPerJob`; remove the silent platform fallback (D14); exclusions fail closed on every path; agent: block `::/128`, reject target-bearing `extra_args`, pin resolved IPs; poll matches tool; Tenable `infra` capability fixed. | api + agent |
| **1 — Zones** | Tables, API, permissions, routing (D4–D6), claim predicate (layer 2), private targets allowed in zones, Scan zones UI, zone picker + routing preview on New scan. | api + ui |
| **2 — Sensors resource** | Sensor roles + capability negotiation (D18–D18b, D20), *Settings → Sensors* (Scanners/Agents/Collectors tabs), enrollment approval, default key TTL + auto-renew, health flags + Update status + quarantine, external engines via bridge (Nessus Pro first), push scopes enforced (D21). | api + agent + ui |
| **3 — Protocol v2 + enforcement in the SDK** | Ed25519 sensor identity + RFC 9421 request signing + key rotation (P1, P2, P4), JWS jobs with a TUF-style key hierarchy (P5, P6, D9), manifest + local allow-list + guarded resolver (D8, D19), typed `extra_args` allow-lists (D11), conformance suite (D23); our agent adopts it; private-target jobs require `signed_jobs`+`zone_guard` (D20); protocol versioning (D24). | sdk-go + agent + api |
| **4 — Credentials, networks, platform, trust, supply chain** | Signed templates/updates (P7), cosign + SLSA L3 + SBOM releases (P8), optional mTLS/SPIFFE (P3); credential tiers T1 vault pull / T2 scoped envelope release (D12); networks + site-aware asset identity (D15); platform shared scanners/zones (D14); trust tiers + verified sensors (D22). | api + sdk-go + agent + ui |

Each phase is shippable alone; Phase 0 is independent and should land first.

## 9. Renaming and compatibility plan

Goal: move to the Sensors vocabulary **without breaking any sensor or SDK in
the field**. Old SDK versions keep working unchanged; where a security feature
needs a newer SDK it is opt-in per sensor, and the platform gives operators a
lever to require it once they have upgraded.

### 9.1 Two axes instead of one `type`

Today `agents.type` mixes *what the sensor does* with *how it runs*
(`runner` = CI one-shot, `worker` = server-controlled daemon, `collector`,
`sensor` = "EASM sensor"; live also has legacy `scanner`). It is split into:

- **role**: `scanner | agent | collector | monitor` (D18); a runtime may hold several.
- **deployment**: `daemon` (long-running, pulls jobs) | `ephemeral` (CI / one-shot, push only).

| Legacy `type` | role | deployment | Note |
|---|---|---|---|
| `worker` | scanner | daemon | today's in-network runtime |
| `scanner` (legacy rows) | scanner | daemon | |
| `sensor` (EASM) | scanner | daemon | internet vantage point; the word *sensor* becomes the umbrella term |
| `collector` | collector | daemon | |
| `runner` | scanner | ephemeral | scans code/images in CI; non-network tools, so no zone routing |

`type` and `execution_mode` stay in the table and in the agent protocol; `role`
and `deployment` are new columns backfilled from them. The API keeps accepting
every legacy `type` value from old clients and maps it.

### 9.2 Compatibility contract (protocol v1 is frozen)

| # | Rule |
|---|---|
| C1 | Every sensor-facing endpoint, auth header, request and response shape of today is **protocol v1** and frozen: changes are additive only, no field becomes required, enum values are only added. |
| C2 | The server accepts v1 payloads forever within a major version. New information (role, features, tool manifest, SDK/protocol version) is sent as **optional** fields on registration/heartbeat; provenance (sensor id, role, zone) is stamped **by the server**, never sent by the SDK. |
| C3 | **New SDK → older server:** the CTIS ingest decoder rejects unknown fields (`ingest_handler.go:387`), so a newer SDK must not add fields to existing payloads blindly. The server advertises its protocol level on every sensor response (`X-OpenCTEM-Protocol`) and a `GET /api/v1/agent/hello`; the SDK sends v2-only data only when advertised and otherwise behaves exactly as v1. |
| C4 | Management API (used by our UI): additive `role` / `deployment` fields; `type` stays in responses, marked deprecated. No URL renames; the rename is in the UI and docs. |
| C5 | Go SDK source compatibility: no exported identifier is renamed or removed in a minor release. New names are **aliases** (`type SensorRuntime = Agent`, role constants); `// Deprecated:` only once the replacement is stable; semver minor bumps. |
| C6 | Deployment compatibility: binary name, environment variables (`API_URL`, agent key, `BOOTSTRAP_TOKEN`, `AGENT_ALLOW_PRIVATE_TARGETS`), Helm values (`agent.*`) and image names are unchanged. |
| C7 | Security features ride on top of v1: the job signature is an additive envelope a v1 SDK ignores; a sensor is switched to "signature required" only after it reports `signed_jobs`. A **minimum sensor protocol** setting (platform-wide, overridable per tenant; default v1) is the operator's upgrade lever: raising it stops new *jobs* to older scanners (collectors keep pushing, D24). The Sensors page shows the fleet by SDK/protocol version so upgrades can be planned. |
| C8 | Proven in CI: a compatibility job runs the **previous released** agent/SDK against the new API (register, heartbeat, poll, claim, push CTIS, renew key), plus golden fixtures of recorded v1 payloads. |

### 9.3 Rollout

| Step | Change | Breaks anything? |
|---|---|---|
| R0 | UI and docs rename: *Settings → Sensors* (Scanners · Agents · Collectors · Scan zones · Networks); `/agents` redirects; role shown from the server-derived mapping. | No (UI only) |
| R1 | API: `role` + `deployment` columns backfilled; optional heartbeat fields; protocol advertisement; fleet version inventory; management responses gain `role`. | No (additive) |
| R2 | SDK minor release: aliases, role/feature/manifest reporting when the server advertises v2, signature verification when present. Our agent bumps to it. | No (opt-in) |
| R3 | Security switches: per-sensor "signature required", tenant "require guarded scanners for private targets", platform minimum protocol. Defaults keep v1 working; operators raise them when their fleet is upgraded. | Only when an operator raises the minimum |

## 10. Sensor fleet security: use cases and controls

The platform must always know what every sensor is doing, notice when one goes
quiet or misbehaves, and keep a compromised sensor from reaching anything
beyond its own narrow lane, in both directions (sensor → platform and
platform → sensor). Each use case below names the control that answers it.

### 10.1 Visibility: the platform always knows the state of every sensor

| # | Use case | Control |
|---|---|---|
| V1 | A sensor stops connecting (crash, network cut, host powered off) | Heartbeat at poll cadence; states **online → late → offline → lost** after N missed intervals; per-tenant alert (in-app + notification channels) at *offline*, escalation at *lost*; fleet health on the Sensors page. |
| V2 | A sensor is connected but does no work ("silent") | Per-job lease + progress watchdog: no progress before lease expiry ⇒ job re-queued to another scanner in the zone, sensor marked *degraded*; job success-rate per sensor tracked. |
| V3 | A zone has no healthy scanner | Coverage alert per zone; New-scan preview shows which targets would be skipped. |
| V4 | Assets stop being scanned | Freshness SLO per zone (assets not scanned in N days) with alert (extends RFC-007 coverage stats). |
| V5 | Sensor runs an outdated or vulnerable version | Heartbeat reports SDK/protocol/tool versions; platform advisories + minimum version (C7); *upgrade required* flag. |
| V6 | Sensor configuration drifts from what the platform set | Heartbeat carries a hash of effective config (allowed ranges, tools, limits, template set); mismatch ⇒ *config drift* flag and alert. |
| V7 | Sensor clock is wrong (breaks signatures and expiries) | Skew measured on every signed request; warn at 1 min, refuse at 5 min. |
| V8 | Fleet inventory goes stale | Sensors with no heartbeat for 30 days are auto-disabled (keys revoked), and reported for decommission. |

### 10.2 Control: the platform governs sensor behaviour

| # | Use case | Control |
|---|---|---|
| K1 | Stop a sensor now | Typed, signed remote actions: **pause / resume / drain / quarantine / revoke / rotate key / force re-enroll / apply config / update**. No shell or free-form command exists. |
| K2 | Stop all scanning during an incident | **Kill switch** per tenant and platform-wide: no new jobs, running jobs cancelled at next poll. |
| K3 | Limit how hard a sensor scans | Policy per sensor/zone: allowed tools, max concurrency, packets-per-second / intensity, **scan windows and blackout windows**; enforced by the SDK locally and by dispatch. |
| K4 | A job must not run late or forever | Job `exp` in the signed envelope, max runtime, cancel propagation; expired jobs are never executed after a reconnect. |
| K5 | Change what a sensor may do | Role/capability approval per role (D18a); removing a tool from the manifest or policy takes effect at the next poll. |

### 10.3 Containment: a compromised sensor cannot spread to the platform

| # | Use case | Control |
|---|---|---|
| C-1 | Attacker steals a sensor's identity | Private key never leaves the host (P1); request signing (P2) means captured traffic is useless; identity bound to host fingerprint ⇒ **the same identity used from two hosts or a new host fingerprint ⇒ quarantine**; unusual source IP/ASN ⇒ alert. |
| C-2 | Compromised sensor calls other APIs | Sensor credentials only work on the sensor route group (no user/admin/tenant-data APIs); it can read only its own jobs and config; tenant from identity, never the body. |
| C-3 | Compromised sensor floods or crashes the API | Separate rate limits, concurrency and quotas for sensor traffic (bulkhead from user traffic), limits applied **before** decompression; bounded decompression everywhere (the ingest-chunk zstd bomb, api#554); per-tenant asset/finding quotas. |
| C-4 | Compromised sensor poisons data | Push scopes (D21): reportable tool names must be in its manifest/job; results outside its zone or job are quarantined; mass auto-resolve or zero-finding "blinding" reports are held for review; provenance on every record. |
| C-5 | Clean up after a compromise | **Purge or roll back everything a sensor wrote in a time window** (findings created/resolved, assets, evidence), driven by provenance; findings it auto-resolved are reopened. |
| C-6 | Sensor-supplied content attacks users or the server | All sensor strings are untrusted: escaped in the UI, markdown sanitised; the server never fetches a sensor-supplied URL except through the SSRF-guarded client; filenames and ids are validated. |
| C-7 | Compromised sensor harvests credentials | Credentials released per job, only for in-range targets, envelope-encrypted to that sensor (D12); custom sensors never get control-plane credentials; every release audited; SSH keys preferred over passwords. |
| C-8 | Compromised sensor forges validation or job outcomes | Evidence and outcomes accepted only for a job assigned to that sensor and still open; state transitions validated (no "fail" after "complete"). |

### 10.4 Reverse containment: a compromised platform cannot weaponise sensors

| # | Use case | Control |
|---|---|---|
| R-1 | Platform tells a scanner to scan something outside its network | Operator-held local allow-list intersected with the signed manifest (D8); built-in deny list (loopback, link-local/IMDS, `::/128`, control plane) on resolved, pinned IPs. |
| R-2 | Forged or replayed jobs | JWS envelopes, offline root key, nonce + expiry, addressed to one sensor (P5, P6). |
| R-3 | Malicious update or template | TUF-signed updates and templates with rollback protection (P7); signed releases (P8). |
| R-4 | Platform asks for shell access | Not part of the protocol; the SDK has no such verb. |

### 10.5 Detecting a compromised sensor

| # | Use case | Control |
|---|---|---|
| D-1 | Binary or tools replaced on the host | Sensor reports the digest of its binary and tools; mismatch with the signed release ⇒ quarantine (TPM-based attestation later). |
| D-2 | Sensor lies about results ("blinding") | **Canary jobs**: the platform periodically schedules a scan of a known canary target with known findings; a scanner that misses them is flagged. Cross-check when two scanners cover the same zone. |
| D-3 | Abnormal behaviour | Baselines per sensor: auth failures, renew rate, job volume, result volume, new-asset rate; deviations raise alerts and can auto-quarantine. |

### 10.6 Disconnection and recovery

| # | Use case | Control |
|---|---|---|
| N-1 | Network partition mid-job | Results buffered locally (encrypted, bounded, file mode 0600), retried with `Idempotency-Key`; the platform re-routes after lease expiry; duplicates are dropped. |
| N-2 | Platform unavailable | Exponential backoff with jitter; the sensor never starts work that was not assigned and signed. |
| N-3 | Key expires while offline | Short grace window for renewal signed by the old key; otherwise re-enrollment with approval. |

### 10.7 Lifecycle, audit and response

| # | Use case | Control |
|---|---|---|
| L-1 | New sensor appears | Single-use enrollment token, approval before any job (D10). |
| L-2 | Sensor decommissioned | Revoke keys, delete released credentials, keep provenance for history. |
| L-3 | Everything must be reviewable | Every enrollment, approval, policy change, remote action, job signature, credential release, quarantine and purge goes to the tamper-evident audit log, exportable to SIEM. |
| L-4 | Incident response | Runbook built into the UI: **quarantine → revoke → purge window → re-enroll**, with the affected data listed. |

### 10.8 Findings from the 2026-10-01 platform ↔ SDK review (to fix)

| Sev | Side | Finding | Phase |
|---|---|---|---|
| HIGH | api | Ingest chunk zstd decompression bomb (any agent key could OOM the shared API) | **fixed, api#554** |
| HIGH | sdk | `DefaultCommandExecutor` passes server-supplied targets to scanners with no target validation or path confinement (third-party users exposed; our agent wraps it) | 0 |
| MED | sdk | gitleaks findings send the **full plaintext secret** as the snippet | 0 |
| MED | api | Heartbeat rewrites the whole agent row (can undo an admin revoke or key change) | 0 |
| MED | api | Auto-resolve trusts the reported tool name; any agent key can resolve another tool's findings | 0 (D21) |
| MED | api | Validation evidence accepted for any finding without an assigned validate job | 0 |
| MED | api | Ingest rate limiter runs after decompression; no per-tenant asset/finding quota | 0 |
| MED | sdk | `pkg/platform` targets routes that do not exist on the API; its checks never run | 0 |
| MED | agent | Per-tool images download binaries without checksums, run as root, no provenance/SBOM | 4 (P8) |
| MED | sdk | Template cache path traversal (`TemplateType`, tenant id) | 0 |
| LOW | both | Unbounded response reads; command expiry dropped by the client; scheme-downgrade redirect keeps the key; non-atomic key save; child processes inherit secrets; API key visible in `ps`; chunk DB permissions; regenerate does not revoke renewed keys; `oct_` scope escalation; missing audit events; key scopes unenforced; `Fail` state checks; unvalidated `X-Request-ID`; global 10 MB limit masks the ingest limit | 0–2 |

## 11. Security notes

- The strongest guarantee is layer 3 with an operator-set local allow-list: it
  holds even if the control plane is fully compromised. Layers 1–2 are routing
  correctness; signing (D9) protects against path attackers and database
  tampering, not against an attacker holding the signing key.
- Zone ranges are validated: no `0.0.0.0/0` or `::/0` for private zones, no
  overlap with the built-in deny list, bounded size for scanner capacity.
- Credentials are never logged, never returned by the API, and (T2) leave the
  control plane only inside one job's envelope for in-range targets.
- Everything here is tenant-scoped; a zone or scanner id from another tenant is
  rejected in SQL, not only in handlers.

## 12. Open questions

1. Should a public target in a tenant with zones but no internet-facing scanner
   fall back to platform scanners if the tenant opted in, or be skipped? (Proposal:
   skipped unless the tenant explicitly enabled shared scanners.)
2. Domain/hostname routing: route by resolved IP only (proposal), or also allow
   suffix rules (`*.corp.example`) on zones?
