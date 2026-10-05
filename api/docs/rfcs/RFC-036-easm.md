# RFC-036 — External Attack Surface Management (EASM)

> Status: **Accepted** (2026-10-02). The owner approved decisions O1–O10 as
> recommended (§12.3). The api + ui monorepo cutover has merged, so
> implementation (P0 → P1) is written directly in the monorepo (`api/` +
> `web/`); §9 tracks which phase items have shipped.
> Scope: api + sdk-go + sensor (`openctemio/sensor`, local checkout `agent`) + ui.
> Builds on [RFC-019](RFC-019-certificate-transparency-discovery.md) (CT
> monitoring), [RFC-023](RFC-023-scan-zones-and-scanners.md) (zones, default
> zone, D14 shared platform scanners), [RFC-026](RFC-026-sensor-results-ingest.md)
> (CTIS ingest), [RFC-028](RFC-028-asset-identity-model.md) (asset identity),
> [RFC-030](RFC-030-scan-work-distribution.md) (chunks, per-host politeness),
> [RFC-033](RFC-033-sensor-manifest.md) (tool manifest) and
> [RFC-034](RFC-034-sensor-network-egress.md) (egress; no evasion).
> Architecture page: [easm.md](../architecture/easm.md).
>
> Owner's request (2026-10-02): "Research deeply and plan how to complete the
> EASM part of this system in the best, most complete, most modern way."

## 1. Answer in short

**OpenCTEM already has most of what EASM stores and very little of what EASM
does.** The asset model, relationships, identity resolution, exposure
register, KEV/EPSS, P0–P3 priority, attack paths and "What changed" are built.
What is missing is the loop that commercial EASM products are built around:

1. **Seeds.** There is no place to say "these are our organisations, brands,
   root domains, ASNs and cloud accounts".
2. **Discovery.** It is limited to tenant-triggered sensor scans of typed-in
   targets plus crt.sh. No sensor image ships the recon tools.
3. **Attribution.** There is no confidence, no evidence and no review queue.
4. **Monitoring.** Only DNS, port and certificate changes are tracked, not the
   rest of the attack surface.

The design keeps OpenCTEM's registers and adds that loop:

- **Seeds** live in Scoping › Boundaries. Ownership is proved by the DNS TXT
  verification that already exists for SSO, or by a cloud connector.
- **Passive collectors run on the API** (CT, RDAP, ASN/RIR, DNS-only checks,
  cloud APIs, per-tenant keys for Censys/Shodan/SecurityTrails …). They send no
  packets to the target.
- **Active enumeration and assessment run on sensors.** This is a chained,
  wildcard-aware pipeline: resolve → light ports → HTTP/TLS → nuclei. It uses
  the non-intrusive tier by default and follows RFC-030 politeness.
- **An attribution engine** turns typed evidence into a 0–100 confidence with
  five states, modelled on Microsoft Defender EASM: confirmed, candidate,
  dependency, monitor-only, rejected. Strong evidence auto-confirms; the rest
  goes to a review queue. Decisions teach the engine.
- **Observations** are hashed per facet, so every DNS, port, certificate and
  HTTP change becomes a diff, an exposure event and a notification.
- **Prioritization reuses the P0–P3 engine.** EASM supplies *publicly exposed*
  and *attribution confidence*. It adds no new score.

**Quick wins come first (P0–P1, about 4 weeks):**
- Make what exists honest: the CT monitor never queries domains past the first
  50, sensors ship no recon binaries, and several UI cards are wrong.
- Subdomain-takeover and dangling-DNS checks.
- Email-security posture (SPF/DMARC/MTA-STS).
- Attribution fields on assets.
- CT promotion under verified domains.
- An EASM overview page.

The full loop (seeds, review queue, chained pipeline, monitoring, connectors)
is P2–P5. Lookalike monitoring, opt-in intrusive checks, shared platform
sensors with published IPs and any vendor-risk mode are owner decisions (§12.2).

## 2. Scope

**In scope:** the customer's own internet-facing attack surface, meaning assets
the customer owns or is responsible for. That includes subsidiaries and
acquisitions the customer declares, and infrastructure the customer runs at
cloud, CDN or SaaS providers. Assets are discovered passively and assessed
non-intrusively under the customer's authorization.

### 2.1 Non-goals

- **No internet-wide scanning dataset of our own.** Censys, Shodan and Xpanse
  scan all of IPv4 continuously [9][6][34][90]. That is a data business, and the
  infrastructure and abuse handling it needs are out of proportion for an
  open-source platform. OpenCTEM is **seed-driven**, and tenants can bring keys
  for those datasets (§6.12).
- **No evasion.** As RFC-034 decided: no rotating source addresses or proxies
  to get past a target's rate limit or block. A throttled or blocked target
  makes the sensor back off and report `target_throttled` / `target_blocked`.
- **No active scanning of anything not attributed as confirmed** and inside the
  authorization (§6.3). Candidates, dependencies and lookalikes get passive
  checks only.
- **No third-party / vendor-risk scanning** in this RFC. If it is ever wanted,
  it is a separate mode with passive public data only, and a separate owner
  decision (§7, O6).
- **No takedown service** for lookalike domains, even if O5 brings lookalike
  monitoring in.
- **No new risk score.** RFC-017 already counts four competing scores.

## 3. Current state (verified 2026-10-02)

Verified on: api `origin/develop` 70a0d08f3, ui `origin/develop` cc9ebfe9,
sdk-go `origin/main` 8324670, sensor `origin/main` 679e974. Three read-only
passes covered the api, the ui with sdk-go and sensor, and the industry
research. Items marked *needs runtime check* were read in code, not run.

### 3.1 Map by stage

| Stage | Built | Partial | Missing |
|---|---|---|---|
| **Seeds / org model** | `verified_domains` (DNS TXT, re-verified every 12 h; migration 000191), used only for SSO JIT. Scope target types include `domain`, `ip_range`, `cidr`, `cloud_account`, `email_domain`, `mobile_app` | Scope targets feed coverage stats and `/scope/check` only; they neither seed discovery nor gate scans (RFC-023 D17's "require in scope" setting is not built) | Seed concept; organisation/brand/subsidiary model; ASN and netblock asset types |
| **Passive discovery** | CT monitor: crt.sh, daily, SSRF-guarded; emits `subdomain_discovered` and `certificate_expiring` exposures (`internal/app/certmonitor`) | Queries only `domain`-type assets, **at most 50 per tenant and always the same first 50** (`listDomains`, no cursor): tenants with more domains never get the rest queried. Results never become assets | Passive DNS, RDAP, ASN/RIR, reverse DNS, Censys/Shodan/SecurityTrails, cloud connectors (providers aws/gcp/azure declared in `pkg/domain/integration/entity.go` with no client; `internal/app/connector` is interface only), GitHub org, mobile apps, lookalikes |
| **Attribution** | Relationship confidence (high/medium/low); dedup review queue for identity conflicts (RFC-028) | `asset_sources.confidence` exists (migration 000014) but its repository is never constructed; `data_sources` has no reader or writer | Asset-level confidence, evidence, review queue, feedback |
| **Enumeration** | sdk-go wrappers: subfinder, dnsx, naabu, httpx, katana; recon CTIS converter; ingest `/ingest/recon`; relationships `contains` (root → subdomain), `resolves_to` | Sensor `internal/executor/recon.go` has its own wrappers and parsers. It is **off by default** (`-enable-recon=false`), yet when enabled it advertises recon capabilities without checking the binaries. **No image ships subfinder/dnsx/httpx/naabu/katana** (`full`/`platform` contain semgrep, betterleaks, trivy, nuclei). httpx favicon, JARM, ASN and certificate fields are parsed and dropped (`core.LiveHost` lacks them). No certificate asset comes from a live handshake. One tool per job; pipeline steps share one context and **never pass outputs to the next step** (`internal/app/pipeline/run.go`). Seeded preset pipelines reference tools nothing provides (amass, tlsx, nmap, ffuf, dalfox, sqlmap; migration 000061) | Wildcard detection (dnsx `-rw` is passed; *needs runtime check* that it is a valid flag), permutation (alterx), tlsx, cdncheck, asnmap, screenshots, `cname_of` emission |
| **Assessment** | nuclei on sensors (`full`/`platform` images); sdk-go `NewTakeoverScanner` preset (tags `takeover`); exposure bridge: certificate assets → `certificate_expiring`/`certificate_expired`/`ssl_issue`, service assets → `port_open`/`service_detected` | Takeover hits arrive as generic vulnerability findings. Nuclei default excludes only dos/local/fuzz/bruteforce/txt-service [67], so `intrusive` (622 templates [66]) runs unless excluded | Dangling-DNS check, email security (SPF/DMARC/MTA-STS; `DomainMetadata` has the keys, nothing evaluates them), open buckets, exposed management interfaces as a class, leaked-credential lookup, intrusiveness tiers |
| **Prioritization** | KEV + EPSS (global, daily); P0–P3 with internet-accessible, reachability, effective criticality; attack paths and exposure chains from public entry points | Attack-surface `/stats` trend fields are hard-coded 0 (`surface_service.go:177-180`) | Attribution confidence as an input |
| **Monitoring** | `asset_state_history` (appeared, disappeared, newly exposed, exposure changes); `asset_discovered` trigger; throttled new-internet-facing notification ([change-detection.md](../architecture/change-detection.md)) | "Shadow IT" view is always empty: nothing sets asset scope `shadow` or `external` automatically | DNS/port/certificate/HTTP diffs: `dns_change`, `port_closed`, `service_changed`, `subdomain_removed`, `bucket_public`, `api_exposed`, `header_missing` exposure types exist with no producer. Cadence tiers |
| **Workflow** | Ownership (two models unified in api#520), ticketing, validation (RFC-011), reports | — | EASM-specific report section; review-queue SLA |
| **Scanning infra** | Scan zones with a default zone for public targets (RFC-023 P1); exclusions fail closed on every scan path | RFC-030 politeness (`per_host`, `limits`) accepted but not built (P4); RFC-034 not built | Shared platform sensors (`CanUsePlatformSensors` returns false in OSS, `internal/app/adapters.go:127,186`); published scanner IPs; scan authorization record |

### 3.2 UI pages

| Route | Verdict | Notes |
|---|---|---|
| `/attack-surface` | Real | Its own endpoint; trends are 0 (API) |
| `/attack-surface/external` | Partial | `useAssets` with `pageSize: 100`, everything else client-side; **"Expiring certs" is always 0** (reads `a.sslExpiry`, never mapped, and certificates are not in the type list); "Technologies" shows tags |
| `/assets/domains`, `/ip-addresses`, `/services` | Real | Shared `AssetPage` over `/assets?types=` |
| `/assets/certificates` | Partial | A certificate without `cert_not_after` shows as **valid** |
| `/assets/websites` | Partial | Missing `http_status` shows as **200** |
| `/assets/changes` | Real | State-history endpoints |
| `/attack-paths`, `/exposure-chains`, `/exposures` | Real | |
| `/exposures/{vulnerabilities,secrets,code,misconfigurations}` | Partial | Side cards show tenant-wide numbers under type titles; none covers nuclei/`easm` sources |
| `/scoping`, `/scope-config` | Real | |

**No EASM page is a scaffold.** Discovery and EASM have no `useDashboardStats`-only
pages. Every new page in this RFC gets its own endpoint, and
`sidebar-no-scaffolds.test.ts` keeps it that way.

### 3.3 Defects found (feed P0)

| # | Defect | Where | Effect |
|---|---|---|---|
| E1 | CT monitor takes the first 50 domains every run, no rotation | `certmonitor/service.go` `listDomains` | Domains 51+ are never monitored |
| E2 | No sensor image ships recon tools; recon executor off by default and advertises unbacked capabilities | sensor `Dockerfile`, `main.go:220`, `recon.go` | Recon jobs cannot run anywhere a stock image is used |
| E3 | Possible flag misuse, *needs runtime check*: dnsx single target via `-d` (dnsx's brute-force domain flag), naabu scan type as bare `-c`/`-s` (`-c` is worker count), katana scope via `-cs` (regex) rather than `-fs` | sdk-go `pkg/scanners/recon/*`, sensor `recon.go` | Wrong or empty results |
| E4 | subfinder parser labels every result `domain`; the converter says `subdomain` | sdk-go `subfinder/parser.go` | Type drift on the native path |
| E5 | httpx favicon/JARM/ASN/cert parsed then dropped | sdk-go `httpx/scanner.go` | Pivots and certificate assets lost |
| E6 | Pipeline steps never receive the previous step's output | `internal/app/pipeline/run.go:300-311` | "Full Reconnaissance" preset cannot chain |
| E7 | Preset pipelines reference amass, tlsx, nmap, ffuf, dalfox, sqlmap | migration 000061 | Presets fail with "scanner not found" |
| E8 | UI external page: 100 cap, expiring certs 0; certificates without expiry show valid; websites without status show 200 | ui `attack-surface/external`, `assets/certificates`, `assets/websites` | Healthy-looking numbers with no data behind them |
| E9 | `/attack-surface/stats` trend fields hard-coded 0; *likely* `website` bucket under-counts because ingest stores websites as `application` | `internal/app/attack/surface_service.go` | Misleading overview |
| E10 | Nothing sets asset scope `external`/`shadow` | ingest | Shadow-IT view empty |
| E11 | RFC index table split by a stray blank line after RFC-020 | `docs/rfcs/README.md` | Rows from RFC-021 on render outside the table (**fixed in this PR**) |

## 4. What the market does

Vendor documentation was read on 2026-10-02. Marketing-only sources are marked
[W] in §14.

| Product | Seeds | Discovery model | Attribution | Active depth and cadence | Scanner IPs |
|---|---|---|---|---|---|
| **Microsoft Defender EASM** (ex-RiskIQ) | Org names, domains, IP blocks, hosts, email contacts, ASNs, WHOIS orgs, cert CNs; grouped into discovery groups with exclusions [3] | Own internet scan + recursive pivots: WHOIS registrant/email/NS, co-resolution, MX, shared certs, ASN; confidence drops at 3rd/4th hop [1] | **Approved / Dependency / Monitor only / Candidate / Requires investigation** [2] | Approved assets daily, discovery weekly by default [2][3]; billed per host:IP pair, domain, active IP seen in 30 days [4] | Not found |
| **Palo Alto Cortex Xpanse** | Seed terms built by their research team [5] | Internet-wide: ~250 ports twice weekly; Known Assets Monitoring daily, **opt-in after range validation** [6] | Very high / High / Medium; tags *Has your content*, *Registered to you*, *Discovered*, *Provided*; evidence = seed term + matched datum [5] | Attack Surface Tests: daily benign exploits [7] | **Published** (9 IPv4 blocks, 3 IPv6 /64s) [6] |
| **Censys ASM** | Domains, DNS names, IPs, CIDRs, ASNs + cloud connectors [10][12] | Internet Map: 100+ ports, rescans anything older than 24 h, ~16 h average age; never logs in [9] | Discovery **paths**; excluding a node removes everything discovered through it [11] | Dangling CNAME/NS daily, "with takeover" = high [13] | **Published** ASNs and opt-out [8] |
| **Mandiant / Google ASM** | 14 typed seeds incl. ASN, netblock, GitHub account, S3 bucket, **UniqueToken** (analytics ID) [15] | Collections → entities → issues; cloud/DNS-provider integrations [19] | Confidence per entity, automatic in/out of scope [15] | **Active** benign checks vs **passive inference** from versions [18] | **Published** [16]; opt-out via support [17] |
| **Tenable ASM** (Bit Discovery) | Domains; suggested domains with the rules that produced them [21] | Asset = (IP, FQDN, record type, value); TCP only [24] | Per-asset **timeline**: source, rule, time [22]; rule count ≈ likelihood [21] | Fortnightly or daily SKUs; rules every 24 h [23] | Not found |
| **Rapid7 Surface Command** | Registered domains and public networks; dynamic seed queries [25] | Correlation across connectors (CAASM) | Not documented | Not documented | Not found |
| **ProjectDiscovery Cloud** | Domains, ASNs | Chaos dataset, brute force + permutation, CT, ASN, Shodan/Censys/FOFA, subsidiaries [27] | "Associated domains" with typed evidence (acquisition, cert history, WHOIS history) [28]; asset policies [29] | nuclei | Dedicated scan IPs (Enterprise) [30] |
| **Shodan Monitor** | Networks, domains, queries [33] | Whole internet at least weekly; on-demand 1 credit/IP [34] | — | Banner-level only | Not applicable |
| **Detectify**, **runZero**, **CyCognito**, **Hadrian** | Root domains / ranges, ASNs, domains | Seed-driven (Detectify, runZero hosted explorer [32]) or "seedless" (CyCognito [37]) | CyCognito "discovery evidence" [37] | Payload-based tests (Detectify [31]); agentic validation (Hadrian [38]) | Not verified |

**Patterns to copy:**

1. **Typed seeds**, including pivot *tokens* (analytics IDs, favicon hashes) [15][36].
2. **Five attribution states** with a separate *dependency* state for
   provider-hosted assets [2].
3. **Evidence = seed + matched datum + rule + time** [5][22]. Users trust
   attribution they can read.
4. **Path-based exclusions:** excluding a parent removes its descendants unless
   another path supports them [11].
5. **Passive inference separated from active checks** [18]. Active depth is
   opt-in after ownership is validated [6].
6. **Daily cadence for confirmed assets, weekly for discovery** [2][3][6].
   Dangling DNS is checked daily [13].
7. **Published scanner ranges, reverse DNS, an information page and opt-out**
   [6][8][16][91]. The ZMap scanning guidelines [87] are the norm; a 2025 study
   found ~70% of survey scanners do not identify themselves [89].
8. **Cloud and DNS-provider connectors as first-party truth**, ranked above
   inference [5][19].

Intrigue Core, the open-source EASM engine Mandiant acquired, is gone (its
repository returns 404) [20]. The closest open-source product is reNgine, a
reconnaissance suite rather than an attribution engine (§4.1). No peer-reviewed system for organisation → internet-presence
attribution was found. Vendor practice is the state of the art, and our rules (§6.4) are built
from it.

### 4.1 Open-source reference: reNgine

The owner pointed at reNgine [104] (GPL-3.0, the same licence as OpenCTEM;
read at commit `de41992`, 2025-11-16) as a model worth learning from. It is a
single-host Django + Celery recon suite for pentesters and bug-bounty hunters.
What it does, read from the code rather than the README:

- **Scan engines are YAML** (`default_yaml_config.yaml`,
  `web/fixtures/default_scan_engines.yaml`): one block per stage
  (`subdomain_discovery`, `port_scan`, `fetch_url`, `dir_file_fuzz`,
  `vulnerability_scan`, `screenshot`, `waf_detection`, `osint`) with
  `uses_tools` and per-tool settings (threads, rate limit, ports `top-100`,
  nuclei severities/tags, out-of-scope regexes). Users edit and save their own
  engines; six presets ship.
- **The stage graph is fixed in code** (`reNgine/tasks.py`, `initiate_scan`):
  `(subdomains ∥ osint) → ports → fetch_url → (fuzz ∥ nuclei ∥ screenshots ∥
  waf)`. A stage absent from the engine is skipped. **Data passes through the
  database:** each stage reads the `Subdomain` / `EndPoint` rows the previous
  stages wrote for the same scan.
- **Subscans:** any subdomain in the results can be sent to a single stage
  (ports, nuclei, screenshot …) without re-running the pipeline.
- **Inventory UX:** per-target pages with subdomains, endpoints/URLs (gau,
  waybackurls, katana, gospider, hakrawler), technologies, IPs/ports with
  geo/ASN, WHOIS and related domains, a screenshot gallery, and **"interesting"
  subdomains and URLs** matched by keyword on name, title or URL
  (`InterestingLookupModel`, default `admin, ftp, cpanel, dashboard`).
- **Monitoring:** periodic or clocked scans; the change view is the set
  difference of subdomains between the last two scans (`startScan/models.py`),
  with Slack/Discord/Telegram notifications for new subdomains and
  vulnerabilities.

**What we take:**

| Idea | Where it lands |
|---|---|
| Declarative, user-editable engine definitions: a stage list with per-tool settings, shipped presets, validated server-side | P3: the "External discovery (T1)" preset (§6.6) is expressed as such a definition, so tenants copy and edit it instead of building pipelines step by step |
| Stage-to-stage data passing (subdomains → ports → HTTP probe → screenshots → endpoints → nuclei) | P3 (E6): the step-output chaining in §6.6, with `active_allowed` and exclusions applied at every hop, which reNgine does not have |
| Subscans from any result | P3: "Scan this" on an asset, a domain group or a review-queue row runs one stage (or a short engine) on that selection, through the normal scan path (zones, politeness, tier ceiling) |
| Recon inventory UX: screenshot gallery, endpoints/URLs, technology stack, WHOIS/IP/ASN panels | P3 (screenshots, endpoints from katana and passive URL sources) and the Inventory tab (§6.11) |
| "Interesting" names and URLs by keyword | P1–P2: a per-tenant keyword list (admin, vpn, jenkins, staging, dev, test, old …) that tags assets and raises their review-queue rank; never a finding on its own |
| Continuous monitoring with change notifications | P4: facet observations and diffs (§6.5) are the richer version of reNgine's subdomain set difference; notifications go through the existing outbox and channels |

**What we keep ours / do not copy:**

| reNgine behaviour | Ours instead | Why |
|---|---|---|
| One host runs every tool (Celery workers next to the web app); results in that host's database | Multi-tenant platform, distributed **sensors** in scan zones (RFC-023, RFC-030, RFC-033) | Scans must leave from the tenant's chosen vantage point, with per-host politeness and an auditable source IP |
| The Full Scan engine fuzzes directories and files (`dir_file_fuzz`); dalfox XSS and CRLF fuzzing are one switch away; nuclei runs every severity by default | **Non-intrusive by default** (O3): T1 nuclei excludes intrusive, default-login, fuzz, dos and bruteforce; fuzzing and payload tests are T2 only, opt-in per scope target with a verified seed, a named approver and an expiry | Our users scan production estates they own, not bug-bounty scopes |
| A target is whatever domain the user types; out-of-scope is a regex list per scan | Scope governance: boundaries, exclusions that win everywhere, verified domains, attribution states (§6.3–6.4) | "Who authorized this probe?" must have an answer |
| OSINT on people (employees and emails via theHarvester, h8mail breach lookups) and search-engine dorking | Not adopted. Leaked-credential lookups only through HIBP with a tenant key (P5) | Personal data and search-engine terms of service |
| GPT-written vulnerability reports and attack suggestions | Not in EASM scope; the platform's AI triage applies to EASM findings as to any other source | Separate feature with its own review |
| Results and prioritisation per scan | CTEM prioritisation (P0–P3, KEV/EPSS, reachability, effective criticality) over one inventory | EASM output joins the same register as every other source |

**Licence.** reNgine is GPL-3.0, like OpenCTEM. We take design ideas only; it
is Python and none of its code is reused. If a file is ever adapted, it keeps
reNgine's copyright notice and attribution.

**Sequencing.** These ideas shape P3 (chained pipeline, engine definitions,
subscans) and the inventory UI. P0 and P1 continue as planned. P3 is not built
before the owner approves the separate scans proposal, which may define the
same pipeline model; the two are reconciled then rather than built twice.

## 5. Techniques by stage

### 5.1 Seeds and the organisation model

| Seed kind | Expands by | Ownership proof |
|---|---|---|
| Organisation / subsidiary / brand name | RDAP registrant org (pre-2018 records, or where not redacted), certificate subject O, as2org (AS → org) [103] | Asserted |
| Root domain | CT, passive DNS, subfinder sources, DNS brute force/permutation, NS/MX co-hosting | `verified_domains` DNS TXT |
| ASN | RIR/BGP announced prefixes (RIPEstat [53], Team Cymru [52]) | Asserted; RPKI ROA origin match is supporting evidence [54] |
| CIDR / netblock | Reverse DNS, TLS SANs of hosts in the block | Asserted; RIR record org match is evidence |
| Cloud account (AWS/Azure/GCP) | Route 53 / DNS zones, public IPs, load balancers, buckets [55][56][57] | Connector credential = proof |
| GitHub organisation | Public repos → secret scanning [58] | OAuth app install or asserted |
| Analytics / tag ID, favicon hash | Search-engine pivots (Shodan `http.favicon.hash`, `google_analytics` [36]; httpx `-favicon` mmh3 [63]) | Asserted, weak |
| Mobile publisher | App-store listings → API hosts in app metadata | Asserted; no primary vendor documentation found, so it is listed and not designed further |

**Registrant data after GDPR.** The ICANN Temporary Specification (2018) and
the Registration Data Policy (effective 2025-08-21) redact registrant personal
data. Port-43 WHOIS is no longer required for most gTLDs since 2025-01-28;
RDAP (RFC 7480/9082/9083/9224) replaces it [47][48][49]. Reverse WHOIS is
therefore weak evidence for modern registrations. Xpanse names redaction as a
reason evidence is missing [5]. We use RDAP for nameservers, registrar and
dates, plus org where present, and never treat a missing registrant as negative
evidence.

### 5.2 Passive discovery

- **Certificate Transparency.** RFC 6962 [39], with RFC 9162 [40] not deployed
  in Chrome's list. In Google's log list v3 (2026-10-01), most usable logs are
  **tiled (static-ct-api)** [41][42]. A direct log tailer must speak both APIs.
  CT names are mined by attackers minutes after issuance [46], so CT is also a
  monitoring signal, not only discovery.
  - **crt.sh** is free and returned 502 during this research [45]. Its usage
    limits are not published. It must not be the only source.
  - **Cert Spotter** (SSLMate): free 100 host + 10 domain queries/hour [43].
  - **CertStream:** free firehose, self-hostable [44].
- **Passive DNS.** Mostly commercial (DNSDB now DomainTools; SecurityTrails
  quota-based [51]). CIRCL pDNS is limited to trusted partners [50]. Per-tenant
  keys only.
- **ASN/BGP/RIR.** Team Cymru IP-to-ASN (free; use DNS for recurring jobs; bulk
  "a few thousand" per batch) [52]. RIPEstat (no hard cap, 8 concurrent per
  IP, `sourceapp` required, register if >1k/day) [53]. bgpview.io no longer
  resolves (2026-10-02).
- **Reverse DNS.** Rapid7 Project Sonar is approval-gated and commercial since
  2022 [26]. We do PTR lookups ourselves, only for seeded/confirmed netblocks.
- **Search engines of scan data** (Censys, Shodan, FOFA, ZoomEye, Netlas,
  LeakIX, urlscan): per-tenant keys. Their terms differ (§6.12).
- **Cloud connectors:** AWS Config / Route 53 `ListResourceRecordSets`, Azure
  Resource Graph, GCP Cloud Asset Inventory [55][56][57]. These are
  authoritative, read-only, and the strongest attribution there is.
- **SaaS discovery** (custom domains CNAME'd to SaaS providers) falls out of
  DNS resolution. The CNAME target's provider is recorded as `hosted_by`, and
  the asset is a *dependency* candidate.
- **Lookalikes.** dnstwist-style permutation (Apache-2.0) with homoglyphs [59].
  Unicode UTS #39 confusable skeletons [60]. Check registration (DNS/RDAP),
  MX presence and CT issuance. Academic basis: email typosquatting [102].
- **Code and secrets.** GitHub secret scanning is free on public repositories
  [58]. Our sensor's betterleaks can scan an org's public repos.

### 5.3 Enumeration and fingerprinting

- **Wildcard detection.** The puredns method [61]: per DNS level, resolve
  several random labels. If they answer, record the wildcard answer set and drop
  candidates whose answers fall inside it, re-checking with trusted resolvers
  to defeat poisoning and load-balancing. puredns, massdns and shuffledns are
  GPL-3.0, so **we implement the algorithm in Go in sdk-go** over dnsx
  (MIT) rather than ship GPL code inside the SDK.
- **Light ports.** naabu connect scan, top-100 by default, at the RFC-030
  per-host limit. No SYN scan from shared sensors.
- **HTTP/TLS.** httpx [63] (title, status, server, tech via wappalyzergo (MIT)
  [65], CDN, favicon mmh3, JARM, ASN, final URL, IP) plus tlsx for the leaf
  certificate (SANs, issuer, validity, key, self-signed, mismatch). CDN/WAF via
  cdncheck. All ProjectDiscovery tools named here are MIT [62].
- **Screenshots** (optional). gowitness is GPL-3.0 [64]. It may ship as a
  separate executable in the sensor image (the same pattern as other tools),
  never linked into the SDK.
- **API endpoints.** katana's known-files and JS crawl, and OpenAPI/GraphQL
  well-known paths, under the T1 tier.

### 5.4 Assessment

| Check | Tier | How |
|---|---|---|
| Version → CVE | T0/T1 | Technology + version → CPE → existing vulnerability correlation. Marked *inferred* (Mandiant's passive inference [18]); confirmed by a template where one exists |
| nuclei templates | T1 | `-etags intrusive,default-login,fuzz,dos,bruteforce` on top of the default ignore list [67][68]; `-dut` to refuse unsigned templates. Template counts: 622 `intrusive`, 345 `default-login`, 84 `takeover` [66] |
| Subdomain takeover / dangling DNS | T0 + T1 | API: CNAME chain ends in NXDOMAIN/SERVFAIL or at a provider in the can-i-take-over-xyz list (CC-BY-4.0, 36 "vulnerable" fingerprints [69]); NS delegations that are lame/unregistered [72]. Sensor: nuclei `takeover` templates confirm. Basis: Liu et al. [70], Borgolte et al. (released cloud IPs) [71], HostingChecker [73], stale certificates [74] |
| TLS | T1 | Expiry, protocol versions, weak keys/ciphers, hostname mismatch, self-signed; profile = TLSRef "intermediate" (Mozilla's successor guidance) [76]; testssl.sh (GPL-2.0) [75] is reference only, not shipped |
| Email security | T0 | DNS only: SPF (RFC 7208 [77]: missing, `+all`/`?all`, >10 lookups), DMARC (**RFC 9989**, which obsoletes RFC 7489 [79]: missing, `p=none`, no reporting), MTA-STS + TLS-RPT (RFC 8461/8460 [80]); DKIM only for known selectors (RFC 6376 [78]) |
| Exposed management interfaces | T1 | Ports/services in the CISA BOD 23-02 class (remote admin, database, VPN/firewall management UIs) [81]; a class in our service fingerprints, P-class raised by *publicly exposed* |
| Open buckets | T1 | Anonymous list on S3/GCS/Azure names attributed as confirmed (from connectors, CNAMEs, page content). Never guessed names of others |
| Leaked credentials | T0 | HIBP domain search (per-tenant key; free for ≤10 breached addresses) [95]; GitHub org secret scanning [58] |
| Default logins, auth checks, fuzzing | **T2, opt-in** | Only on verified ownership, per scope target, with an expiry (§6.3). Censys never logs in [9]; Xpanse gates deeper payloads behind validation [6] |

### 5.5 Prioritization

CISA's SSVC model for **BOD 26-04** takes *In KEV*, *Publicly Exposed*,
*Automatable* and *Technical Impact* and maps them to response times
(3 days with forensics … fix on upgrade) [84]. *Publicly exposed* is exactly
what EASM produces. *Not verified:* whether 26-04 replaces BOD 22-01; cisa.gov
refused fetches during the research. The KEV catalog has 1,731 entries
(2026.10.01) [82]. EPSS is daily and free [83]. A study of 42,735 internet-facing
devices found no correlation between CVE density and exploitation [86]. That
supports weighting by KEV/EPSS rather than counting CVEs, which is what the P0–P3
engine already does. EASM is the Discovery stage of Gartner's CTEM loop [85]
(fetch refused during the research; the five stages are already OpenCTEM's IA).

### 5.6 Monitoring cadence (market norm)

- Confirmed assets: daily [2][6][9].
- Discovery: weekly [3].
- Dangling DNS: daily [13].
- Whole-internet datasets refresh every 16 h to 7 days [9][34].

## 6. Design

### 6.1 Principles

1. **Passive first, active by tier.** No packet reaches a target until the
   asset is confirmed and authorized; the tier decides how deep.
2. **One asset-creation path.** Discoveries become assets only through ingest
   (RFC-019 §6's concern). Candidates live outside the asset table.
3. **Evidence over verdicts.** Every attribution and every EASM issue carries
   the chain that produced it.
4. **Technique is not channel** (ADR-004). EASM output keeps
   `findings.source = easm`. Which collector or sensor saw it is provenance on
   the sighting and the evidence.
5. **Tenant isolation.** The tenant comes from the seed or asset, never from a
   collector response. Keys are per tenant. Paid results are never cached
   across tenants.
6. **Reuse the registers:** assets, relationships, exposure events, findings,
   state history, notifications, P0–P3. New tables only where there is no home.

### 6.2 Where each stage runs

| Runs on | Stages | Why |
|---|---|---|
| **API, controllers** (per tenant, leased, fail-open, SSRF-guarded `httpsec` client, RFC-034 content proxy) | CT, RDAP, ASN/RIR, PTR of seeded netblocks, DNS-only checks (dangling, email, lookalike resolution), cloud APIs, Censys/Shodan/SecurityTrails/… with tenant keys, HIBP, GitHub API | Third-party APIs and DNS lookups only; no traffic to customer hosts beyond what any resolver sends |
| **Sensors**, as a scan run (RFC-030 chunks, zones, politeness) | Resolution with wildcard filtering, ports, HTTP/TLS, screenshots, nuclei | Touches the target: needs a scan zone, per-host limits, egress control, an auditable source IP |

**DNS checks in the API** use the platform resolver configuration with its own
rate limit. A tenant that forbids that sets `easm.dns_checks_on_sensor` and the
checks run as a sensor job instead.

**Vantage point for the external view:**

- OSS default: the tenant's own sensor in its **default (public) zone**
  (RFC-023). Many tenants place it outside their perimeter, e.g. on a cloud VM.
- Option: **shared platform sensors** (RFC-023 D14). They scan public targets
  only, never hold tenant credentials, are opt-in per tenant, and are labelled
  "shared". They send from **published, stable egress ranges** with
  descriptive reverse DNS, an information web page on each source IP and an
  abuse contact, following the ZMap guidelines [87][88] and the practice of
  Censys, Xpanse, Mandiant and CISA [8][6][16][91]. This is owner decision O2.

### 6.3 Seeds, authorization and tiers

**Table `easm_seeds`**

| Column | Notes |
|---|---|
| `id`, `tenant_id` | |
| `kind` | org_name, brand, root_domain, asn, cidr, cloud_account, github_org, mobile_publisher, analytics_id, favicon_hash |
| `value` | |
| `label` | |
| `scope_target_id` (nullable) | Ties a seed to a boundary |
| `verification` | none / dns_txt / connector |
| `verified_domain_id` | |
| `discovery_enabled` | |
| `created_by`, `created_at` | |
| `attestation` | Who asserted ownership, and when |

UI: Scoping › Boundaries gets a **Seeds** tab next to Targets and Exclusions.
`root_domain` seeds reuse the `verified_domains` DNS TXT flow from SSO. One
verification serves both.

**Authorization to touch an asset actively:**

```
active_allowed(asset) =
      asset.attribution_state = confirmed
  AND NOT excluded(asset)                       -- exclusions always win (as today)
  AND ( in_scope_target(asset) OR derived_from_seed(asset) )
  AND tier(asset) <= tier_ceiling(scope_target or tenant default)
```

**As built (2026-10-04, #1114).** One gate (`internal/app/easm/active_gate.go`)
decides `active_allowed` on every active-scan path: typed targets and
asset-group members, at scan create, clone, import, quick scan, `POST
/commands`, every run (manual, scheduled, retry, workflow) and the dispatch
gate (pipelines, coverage, validation, retests, simulations, connectors).
An asset is allowed when its record is `confirmed`, or, with no record, when
it is inside an active scope target or at/under a root-domain seed or verified
domain (`derived_from_seed`); a rejected name refuses itself and every name
under it. An internet-facing asset with no record outside all of them is
`unattributed` and waits for a person. The tier ceiling is not enforced yet
(sensor side, 22b S7). See
[architecture/active-probe-gate.md](../architecture/active-probe-gate.md).

| Tier | Touches the target | Default |
|---|---|---|
| **T0 passive** | No (third-party data, DNS) | All candidates, dependencies, lookalikes, confirmed |
| **T1 safe-active** | Connect, banner, TLS handshake, GET of known paths, nuclei without intrusive/default-login/fuzz/dos/bruteforce | Confirmed assets (proposed default, O3) |
| **T2 intrusive** | Login attempts, fuzzing, intrusive templates | Off. Per scope target, needs a **verified** seed, a named approver and an expiry; recorded in the audit log |

Every run records the tier, ceiling, approver and source vantage (sensor/zone/
egress) on the scan run. Unauthorized-access law (CFAA, UK Computer Misuse Act)
is the background for this record [101]; it is not legal advice, and the
attestation at seed creation is where the tenant states its authority. "Who authorized this probe?" then has an answer.

### 6.4 Attribution engine

**Tables**

- `easm_candidates`: one row per discovered thing.
  - Columns: `tenant_id`, `kind` (fqdn, ip, netblock, asn, certificate,
    bucket, repo, app), `value`, `state`, `confidence`, `first_seen`,
    `last_seen`, `discovery_path` (parent candidate/asset + edge), `asset_id`
    (after promotion).
  - States: `candidate`, `confirmed`, `rejected`, `dependency`,
    `monitor_only`, `needs_review`.
  - Unique key: `(tenant_id, kind, value)`.
- `easm_evidence`:
  - Columns: `tenant_id`, `subject_type` (candidate | asset), `subject_id`,
    `rule`, `source` (collector or sensor run), `observed` (JSONB, the matched
    datum), `weight`, `polarity` (+/−), `observed_at`.
- `assets` gains `attribution_state` (NULL for legacy rows = confirmed),
  `attribution_confidence` (0–100) and `attribution_reason` (the top rule).

**Confidence** = noisy-OR of positive weights, then discounted by negative
evidence: `c = (1 − Π(1 − wᵢ⁺)) · Π(1 − wⱼ⁻)`, shown as 0–100. It is simple,
monotone and explainable: each row says how much it added.

**Starting rule table** (weights per tenant, adjusted by learning):

| Rule | w | Class |
|---|---|---|
| Returned by the tenant's cloud/DNS-provider connector | 1.00 | strong |
| FQDN under a `verified` root-domain seed | 0.99 | strong |
| IP inside a seeded CIDR, or announced by a seeded ASN | 0.90 | strong |
| Target the tenant scanned itself (scan target or asset it created) | 0.95 | strong |
| FQDN under an asserted (unverified) root-domain seed | 0.85 | medium |
| TLS certificate SAN shared with a confirmed FQDN | 0.50 | medium |
| RDAP registrant org / cert subject O matches an org seed | 0.60 | medium |
| Same analytics/tag ID as a confirmed asset | 0.70 | medium |
| PTR record under a confirmed domain | 0.50 | medium |
| Favicon hash equals a seed or confirmed asset | 0.40 | weak |
| Same nameservers as a confirmed domain (non-shared NS) | 0.30 | weak |
| IP belongs to a CDN / shared hosting (cdncheck, ASN of a provider) | −0.6 | negative → suggests `dependency` |
| Hop count from the seed > 2 | −0.2 per hop | negative (MS EASM: confidence drops at 3rd/4th hop [1]) |

**Decision**

- **Auto-confirm** only when at least one *strong* rule fires and
  `c ≥ auto_threshold` (default 90, O4).
- Otherwise:
  - `c ≥ 50` → `needs_review`;
  - `c < 50` → `candidate`, hidden unless filtered for.
- CDN/provider evidence with a confirmed name → `dependency`. The name is the
  tenant's and the infrastructure is the provider's: T0 checks plus the
  takeover check, never port scans of the provider's IP.

**Review queue**

- Sorted by confidence × potential impact (open ports, high-risk tech).
- Each row shows the evidence chain as sentences, for example: "`api.acme.io`
  — SAN on the certificate also serving `www.acme.com` (confirmed) — seen in CT
  2026-09-30".
- Actions: confirm / reject / dependency / monitor only, with bulk and "apply
  to all with this evidence".

**Learning**

- Each rule keeps a per-tenant Beta(α, β) of confirm/reject outcomes. The
  effective weight is the base weight × posterior mean, floored and capped.
- A rejection writes a **tombstone**. The candidate is not proposed again unless
  a new *rule* (not just a new sighting) supports it.
- Precision per rule is shown on the Overview page.

**Exclusions cascade along discovery paths** (the Censys pattern [11]).
Excluding a node rejects its descendants unless another non-excluded path
supports them.

**Promotion.** A candidate reaching `confirmed` is written through internal
CTIS ingest (RFC-026 semantics, provenance stamped by the server) with its
evidence. Identity resolution (RFC-028) merges it with an existing asset if
there is one.

**Sensor-scan results** keep today's behaviour: assets from a tenant-triggered
scan are created directly. They get the "tenant scanned it" evidence, so the
inventory and the review queue tell one story. Routing those results through
the queue instead is O8.

### 6.5 Data model: the graph and time

- **Nodes:** existing asset types, plus `asn` and `netblock`. The organisation
  is the seed set, not an asset.
- **Edges:** existing `contains`, `resolves_to`, `exposes`, `runs_on`, plus:
  - `cname_of` (now emitted by resolution);
  - `serves_certificate` (service → certificate);
  - `announced_by` (IP/netblock → ASN);
  - `hosted_by` (asset → provider/CDN, as a property-tagged edge to a
    provider-kind node).
- OWASP's Open Asset Model (Apache-2.0, 21 types: FQDN, IPAddress, Netblock,
  AutonomousSystem, TLSCertificate, Service, Organization …) [100] is the
  reference vocabulary. CTIS stays our wire format; a mapping table to OAM goes
  in the architecture page so an importer is easy later.
- **Observations**, append-only, in `easm_observations`:
  - Columns: `tenant_id`, `asset_id`, `facet`, `hash`, `value` (JSONB,
    canonicalised), `observed_at`, `source_run_id`.
  - Facets: `dns` (sorted RRsets), `ports`, `tls_leaf` (fingerprint), `http`
    (status, title, server, favicon, tech set), `rdap`.
  - Only a **changed hash** writes a row. Unchanged observations update
    `last_seen` on the latest row, so storage grows with change, not with scan
    count.
  - A change writes state history and the matching exposure event:
    - `dns_change`
    - `port_open` / `port_closed`
    - `service_changed`
    - `certificate_*`
    - `subdomain_removed`
- **Time:** `first_seen`/`last_seen` on assets, edges and observations.
  The **earliest external evidence** for MTTD comes from CT `not_before` and
  passive-DNS first-seen.

### 6.6 Discovery pipeline on sensors

Pipelines need a server-side change: **step outputs become the next step's
targets** (E6). After each step completes, the pipeline service reads the run's
ingested assets of the declared output types. It filters them through
`active_allowed` and the exclusions, then plans the next step's targets for
RFC-030 chunking. A cap on fan-out per run (default 10k targets, the RFC-030
cap) stops runaway expansion.

**Preset "External discovery (T1)":**

```
seed root domains ─► subfinder (passive sources, per-tenant keys passed as env)
                  ─► alterx permutations (bounded, only under confirmed roots)
                  ─► dnsx resolve + wildcard filter (Go, puredns method)      → domain/subdomain, resolves_to, cname_of
                  ─► naabu top-100 connect, per_host=1                          → ip_address, open_port
                  ─► httpx + tlsx + cdncheck (keep favicon/JARM/ASN/cert/CPE)   → service, certificate, serves_certificate, hosted_by
                  ─► [optional] gowitness screenshot
                  ─► nuclei T1 (etags intrusive,default-login,fuzz,dos,bruteforce; -dut)
```

Each step emits CTIS, so ingest, identity resolution, the exposure bridge and
priority all apply unchanged.

**Sensor work for this:**

- Ship the tools in `full`/`platform`: pinned, checksummed, managed by
  RFC-031 content updates where they have content.
- Advertise them through the RFC-033 manifest only when the binary answers
  `-version`.
- Fix E3–E5 and use one parser (the sdk-go converter), retiring the sensor's
  hand-rolled copies.

### 6.7 Scheduling and cadence

| Tier | Who | Passive collectors | Light active (resolve, ports, HTTP/TLS) | nuclei T1 |
|---|---|---|---|---|
| **A** | Crown jewels, critical effective criticality, internet-facing with P0/P1 history | Daily | Daily | Weekly |
| **B** | Other confirmed external assets | Daily | Weekly | Fortnightly |
| **C** | Dependencies, monitor-only | Daily (T0 only) | — | — |
| **New asset** | First seen in the last 24 h | — | Within 1 h of confirmation | Within 24 h |

- CT runs daily (P0). Near-real-time CT comes later: Cert Spotter with a tenant
  key, or a static-ct-api tailer.
- Dangling-DNS and email checks run daily (cheap; DNS only).
- Discovery from seeds runs weekly, the MS EASM default [3].
- All cadences are tenant-tunable within platform floors, so nobody can
  schedule nuclei hourly on a shared sensor.
- A per-tenant **budget** (targets × tier per day) is visible in the UI.

### 6.8 Prioritization

- EASM findings go through the existing P0–P3 classifier. EASM assets are
  internet-accessible by construction, so the existing *internet-accessible*
  input does the work of SSVC's *publicly exposed*.
- **Attribution confidence becomes a gate, not a multiplier.** An EASM finding
  on an asset below `confirmed` is capped at P2. It carries a "verify
  ownership" action, so nobody gets paged at night for someone else's server.
- Exposure events keep severity and read-time enrichment (reachability,
  effective criticality, EPSS/KEV).
- Takeover-confirmed and KEV-on-exposed-service are the two EASM signals that
  map to P0.
- Exposure chains and attack paths already start at public entry points; they
  gain the new assets automatically.

### 6.9 Workflow

- **Ownership:** a new external asset inherits the owner of its seed's scope
  target or business unit, if set. Otherwise it lands in the existing "no
  owner" queue (api#520 model).
- **Tickets:** the existing ticketing rules apply to EASM findings and exposure
  events. A *review queue age* SLA appears on the Overview.
- **Validation:** RFC-011.2's nuclei re-verify covers T1 findings; takeover
  confirmation reuses it.
- **Reports:** an "External attack surface" section with new assets, open
  exposures, attribution changes and freshness, in the existing report
  scheduler.
- **CTEM cycles:**
  - The charter can pick seed sets.
  - Activation snapshots confirmed external assets of those seeds.
  - Review reports *new external assets this cycle* and *MTTD*. This gives the
    cycle's `scope_drift_size` criterion the data source it lacks today
    (`pkg/domain/ctemcycle/criteria.go:133`).

### 6.10 API sketch

| Route | Permission | Purpose |
|---|---|---|
| `GET/POST/PATCH/DELETE /api/v1/easm/seeds` | `scope:*` (read/write) | Seeds; verification reuses `/verified-domains` |
| `GET /api/v1/easm/summary` | `assets:read` | Overview: attributed counts by state, queue size and age, new in 7/30 days, exposures by severity and type, freshness by tier, coverage, rule precision |
| `GET /api/v1/easm/candidates` (+ `/{id}/evidence`) | `assets:read` | Review queue, filters by state/kind/confidence/rule |
| `POST /api/v1/easm/candidates/decisions` | `assets:write` | Bulk confirm/reject/dependency/monitor-only with reason |
| `GET /api/v1/easm/graph?root=&depth=` | `assets:read` | Bounded subgraph for the graph view |
| `GET /api/v1/easm/observations?asset_id=&facet=` | `assets:read` | Facet history and diffs |
| `GET/PUT /api/v1/easm/settings` | `settings:write` | Cadence tiers, auto threshold, tier ceiling, collectors on/off |

Module gate: the existing `attack_surface` module. Data scope applies to
candidates the same way as to assets.

### 6.11 UI

Discovery › **Attack Surface** becomes the EASM workspace (no URL change for
`/attack-surface`):

- **Overview:** KPIs and trends from `/easm/summary`, the review-queue call to
  action, freshness by tier, recent changes.
- **Inventory:** `/assets` filtered `exposure=public`, plus attribution
  columns. Replaces `/attack-surface/external` (which gets a 308 redirect,
  following openctemio/ui#591's pattern).
- **Review:** candidate table with an evidence drawer, bulk actions, rule chips.
- **Graph:** seed-rooted, expand-on-click, colour by state/severity. Reuses the
  graph component planned for attack paths.
- **Changes:** "What changed" plus facet diffs.
- **Exposures:** existing exposures + `source=easm` findings.

Seeds are edited in Scoping › Boundaries › Seeds.

### 6.12 Integrations: passive sources with per-tenant keys

New integration category `discovery_source`. Credentials sit in the existing
encrypted integration store, resolved by `ListByProvider(ctx, tenantID, provider)`
(the RFC-006 pattern). The tenant comes from the seed. Each provider has a
quota tracker and a per-tenant cache with TTL. Results from licensed sources are
never shared across tenants.

| Source | Key | Default | Terms that matter |
|---|---|---|---|
| crt.sh | none | on | Free; unpublished limits; outages seen [45] — fallback to Cert Spotter |
| Cert Spotter | optional | on (free tier) | 100 host + 10 domain queries/h free; paid tiers [43] |
| RDAP (bootstrap RFC 9224) | none | on | Registry rate limits vary |
| RIPEstat, Team Cymru | none | on | `sourceapp`; ≤8 concurrent; DNS interface for recurring Cymru lookups [52][53] |
| Censys | tenant | off | Free 100 credits/month; research access non-commercial [14] |
| Shodan | tenant | off | Commercial use with attribution; 1 req/s [35] |
| SecurityTrails | tenant | off | Quota-based [51] |
| Chaos (PD) | tenant | off | Commercial use needs Enterprise [94] |
| VirusTotal | tenant | off | Public API **not for commercial products or business workflows** [92]; premium keys only |
| urlscan.io | tenant | off | 1k searches/day free [93] |
| HIBP | tenant | off | Free for ≤10 breached addresses [95] |
| GreyNoise | tenant | off | Context for "who is scanning me", not discovery [96] |
| Netlas, LeakIX, FOFA, ZoomEye | tenant | off | Free tiers personal use or delayed [97][98] |
| BinaryEdge | — | not offered | Service transitioned to Coalition [99] |
| AWS / Azure / GCP | tenant (read-only role) | off | Authoritative; connector framework exists (`internal/app/connector`), clients do not |
| GitHub | tenant (app/token) | off | Public repos only unless the org grants more |

### 6.13 Security, tenancy and safety

- Collectors use `httpsec.SafeHTTPClient`, which follows RFC-034 G2 once it is
  proxy-aware. Bodies are bounded and parsing is strict.
- Collector output is **untrusted data**: names are normalised (IDNA,
  lowercase, length limits) and sanitised before logging, using
  `strings.ReplaceAll` for CR/LF as CodeQL expects.
- Two tenants may claim the same domain. Each gets its own candidates, evidence
  and verifications. **Nothing reveals another tenant's claim**: no "already
  verified by someone" message, and no shared cache keys for licensed data.
- Active steps run only with `active_allowed`. The sensor-side scope check
  (RFC-023 D7/D8) still refuses out-of-scope addresses after resolution.
- Back-off: HTTP 429/503 and connection resets lower the per-host rate (AIMD,
  RFC-030). Repeated blocks mark the target `target_blocked` for the run. **No
  retries from other addresses** (RFC-034 non-goal).
- Every probe is attributable: run, tier, approver, sensor and egress IP.

## 7. Third-party / vendor-risk mode (separate decision)

Vendor-risk ratings use public data about **other** organisations. If the owner
ever wants it (O6), it must be:

- a separate register (`vendors`), never mixed with the tenant's inventory or
  attribution;
- **passive public data only**: CT, DNS, RDAP, licensed scan datasets with the
  tenant's keys and their terms. **No packets from our sensors to vendor
  hosts**, no nuclei, no port scans;
- labelled as outside-in, unverified and point-in-time.

The recommendation is **out of scope for now**. It is a different product
(TPRM), and it would weaken the clear "own surface, authorized" boundary this
RFC rests on.

## 8. Gap list, ranked by value / effort

| # | Gap | Value | Effort | Phase |
|---|---|---|---|---|
| 1 | Sensor images ship no recon tools; recon off; flag bugs (E2–E5) | Very high: nothing below works without it | S–M | P0 |
| 2 | CT monitor starves domains past 50 (E1); `certificate_expired` | High | S | P0 |
| 3 | Dishonest UI numbers (E8, E9) | High (trust) | S | P0 |
| 4 | Dangling DNS / subdomain takeover | Very high (common, severe, cheap) | S–M | P1 |
| 5 | Email security posture | High (every org has a domain) | S | P1 |
| 6 | Attribution fields on assets + evidence (minimal rules) | High (foundation) | M | P1 |
| 7 | CT subdomains under verified domains → assets | High | S | P1 |
| 8 | EASM overview page | Medium–high | S–M | P1 |
| 9 | Seeds + candidates + review queue + learning | Very high (the core loop) | L | P2 |
| 10 | Pivots: RDAP, ASN/RIR, PTR, SAN co-occurrence, tokens | High | M | P2 |
| 11 | Pipeline output chaining + External-discovery preset | Very high | L | P3 |
| 12 | Keep httpx/tlsx fields; certificate assets; `cname_of`, `serves_certificate` | High | M | P3 |
| 13 | RFC-030 politeness (per_host, limits) | Required before daily cadence at scale | M (RFC-030 P4) | P3 dependency |
| 14 | Observations + facet diffs + producer-less exposure types | High | M | P4 |
| 15 | Cadence tiers + budget | Medium–high | M | P4 |
| 16 | Per-tenant passive sources | Medium–high (coverage) | M (S per source) | P5 |
| 17 | Cloud connectors AWS/Azure/GCP | Very high (authoritative) | L | P5 |
| 18 | GitHub org secret exposure | Medium | S–M | P5 |
| 19 | Lookalike / brand monitoring | Medium (O5) | M | P6 |
| 20 | T2 intrusive opt-in | Medium (O3) | M | P6 |
| 21 | Shared platform sensors + published IPs | Medium for OSS, high for hosted (O2) | L + ops | P6 |
| 22 | Vendor-risk mode | Low here (O6) | L | not planned |

## 9. Phased plan

Effort is engineer-weeks across all repos.

| Phase | Content | Effort | Risk | Depends on | Acceptance criteria |
|---|---|---|---|---|---|
| **P0 — Make what exists honest** | E1 CT rotation cursor (oldest-checked first) and `certificate_expired` for the newest cert only; E2 recon tools in `full`/`platform` (pinned, checksummed), recon capabilities advertised only when the binary answers; E3 flags verified against each tool's `-h` and fixed, with golden tests; E4 parser type; E7 presets reference only shipped tools; E8 UI: server pagination, expiring from certificate assets, unknown ≠ valid/200; E9 real trends from state history, website bucket = application/website; E11 README (this PR) | 1.5–2 | Low | — | Tenant with 120 domains: every domain queried within 3 runs. Stock `platform` image + a test domain we own: subfinder → dnsx → httpx produce subdomain/IP/service assets live. UI cards match API counts on a fixture. No new findings from a run with zero data |
| **P1 — Quick wins** | Dangling CNAME/NS check (API, daily, can-i-take-over-xyz fingerprints vendored with attribution) → `dangling_cname`/`dangling_ns` exposures; sensor nuclei `takeover` confirmation → `subdomain_takeover` (high); email posture (SPF/DMARC RFC 9989/MTA-STS/TLS-RPT) → `email_security_weak`; asset attribution columns + `easm_evidence` with the strong rules only; CT subdomains under **verified** domains promoted via internal ingest; `GET /easm/summary` + Overview tab | 3 | Low–medium (false positives on takeover → confirm step before *high*) | P0 | Fixture zone with a CNAME to an unclaimed provider is flagged medium within 24 h and high after confirmation. Fixture domains with `p=none` / no SPF flagged; correct ones not. Every promoted asset shows its evidence. Overview numbers equal list counts |
| **P2 — Seeds and attribution** | `easm_seeds` + Boundaries › Seeds tab; `easm_candidates`, full rule table, noisy-OR, states, tombstones, path-cascading exclusions; collectors RDAP, RIPEstat/Cymru, PTR of seeded netblocks, SAN co-occurrence from CT; Review tab with evidence drawer and bulk; Beta learning; rule precision on Overview | 5–6 | Medium (precision; UI volume) | P1 | On a labelled test set (one real org's surface, ≥200 names), auto-confirmed precision ≥ 0.98 and queue precision ≥ 0.7. Rejected names never reappear without a new rule. Cross-tenant test: two tenants claiming one domain see nothing of each other |
| **P3 — Active discovery pipeline** | Step-output chaining with `active_allowed` at each hop; wildcard filter in Go (puredns method); alterx bounded; naabu top-100; httpx+tlsx+cdncheck fields kept; certificate assets, `cname_of`, `serves_certificate`, `hosted_by`, `asn`/`netblock`; nuclei T1 flags; optional gowitness; one parser (sdk-go) | 5–6 | Medium–high (load on targets; tool behaviour) | P0; **RFC-030 P4 politeness** before enabling daily runs for more than pilot tenants; owner approval of the scans proposal (§4.1) | A wildcard test zone yields 0 false subdomains. One run on a 1k-name surface stays within per_host=1 and the zone `max_rps`. Every finding traces seed → … → asset. Excluded nodes are never probed (sensor log) |
| **P4 — Continuous monitoring** | `easm_observations` facets + hashes; diffs → state history + exposure events (`dns_change`, `port_open/closed`, `service_changed`, certificate change, `subdomain_removed`); cadence tiers + budget; notifications via outbox; MTTD and freshness metrics | 3 | Low–medium (noise) | P3 | Changing a fixture DNS record / opening a port / rotating a cert yields one event each within the tier's cadence. Unchanged rescans write no rows. MTTD shown per asset |
| **P5 — Sources and connectors** | `discovery_source` integrations (Cert Spotter, Censys, Shodan, SecurityTrails, Chaos, urlscan, HIBP, GitHub) with quota + cache; cloud connectors AWS (Route 53, public IPs, ELB, S3), Azure Resource Graph, GCP CAI as authoritative evidence; "cloud public IPs not in inventory" coverage metric | 6–8 (S per source, M per cloud) | Medium (credentials, terms) | P2 | Each source is per-tenant (`ListByProvider`) and isolation-tested. Quota exhaustion degrades to skip + warning. A connector-only asset auto-confirms with w = 1.0 |
| **P6 — Optional modes** (each its own owner decision) | Lookalike monitoring (Go permutations + UTS #39 skeletons; registration/MX/CT checks; `lookalike_domain` exposure; T0 only); T2 intrusive opt-in with approver + expiry; shared platform sensors with published egress ranges, rDNS, info page, opt-out handling | 3 + 2 + (4 + ops) | Medium (legal/ops for platform sensors) | O2, O3, O5 | Lookalikes never receive active probes. T2 runs refuse without a verified seed and an unexpired approval. Published range document matches the actual egress (automated check) |

**Status on `develop` (checked 2026-10-04).**

| Phase | Status |
|---|---|
| P0 | Shipped on the api/web side: E1 CT rotation and retries (#811, migration `000266`), `certificate_expired` for the newest certificate only, E7 presets with shipped tools only (#815, `000270`), E8/E9 honest numbers and real trends (#829), E11 (#724); CT names promoted to assets and the scan attribution gate (#839). Open: E10 (automatic external/shadow scope). E2–E5 are tracked in sdk-go and the sensor. |
| P1 | Shipped: dangling CNAME/NS and email posture checks (#852, `000325`; **off by default**, `EASM_DNS_CHECKS_ENABLED`) and the lame-delegation check (#1012); attribution side tables and evidence, CT promotion and `GET /api/v1/easm/summary` (#839, `000324`); tenant-scan evidence `tenant_scanned` (#1004); the asset Ownership section (#856); the EASM overview cards on `/attack-surface` (#857); the review queue with bulk decisions and the asset-list attribution filter (#994 API, #1023 web: `/attack-surface/review`, inventory shows approved assets by default; [easm.md §4b](../architecture/easm.md)); findings on unconfirmed assets capped at P2 (#1009); takeover confirmation: a nuclei takeover-template match from a tenant scan on an open `dangling_cname` raises `subdomain_takeover` (high) (#1018, `000485`). Open: sensor-side C17 (dnsx resolver fallback, sensor repository). |
| P2 | In progress: seeds (#1041: `easm_seeds`, `root_domain` watched by the CT monitor). Open: candidates and tombstones, CIDR/ASN/organization seeds with RDAP/RIPEstat/PTR collectors, noisy-OR learning, rule precision. |
| P3–P6 | Not started (no `easm_observations`). |

**research/22 P0 (EASM maturity plan, owner decisions E1–E13, 2026-10-04).**
One entry per item; the sensor items (P0-1 to P0-4) live in the sensor and
sdk-go repositories, P0-5 with the scan-engine work (research/27).

- **P0-7 EASM alerts through the notification outbox:** shipped (this PR,
  migration `001014`). The CT monitor, the DNS checks and takeover
  confirmation write exposures through one writer that announces inserted
  and reopened rows as `new_exposure` in the same transaction: immediate for
  medium or higher on approved assets, a daily digest otherwise, never for
  rejected or deleted assets, 30 immediate alerts per tenant per hour.
  [easm.md §4c](../architecture/easm.md#4c-alerts-built-p0-7).

- **P0-8 DNS checks on by default, takeover on dependency names (E3, E13):** open.

- **P0-9 rejection hygiene and reclassify on decision (B2, B4):** open.

- **P0-10 tenant domain verification with a purpose (E6):** open.

- **P0-11 EASM settings and run-now:** open.

- **P0-12 review queue reachable, honest counts (E1):** open.

- **P0-13 honest EASM numbers:** open.

- **P0-6 port and service results surfaced (B6):** open.

**When and where.** Implementation is written directly in the monorepo
(`api/` + `web/`); sdk-go and sensor changes (E2–E5, P3 tools) stay in their
own repositories. P2 may start: P1's attribution tables shipped (migration
`000324`). P3's daily cadence waits on RFC-030 P4.

## 10. Metrics

| Metric | Definition | Target (initial) |
|---|---|---|
| **Coverage, seeds** | Share of seeds with every enabled collector successful in the last 7 days | ≥ 95 % |
| **Coverage, assessment** | Confirmed external assets assessed at their tier's cadence / all confirmed external assets | ≥ 90 % |
| **Coverage, authoritative gap** | Public IPs/DNS names from cloud connectors not in the inventory (lower is better) | → 0 |
| **Freshness** | p50/p95 age of the latest observation per tier | A ≤ 1 d, B ≤ 7 d |
| **Attribution precision** | Confirmed ÷ (confirmed + later rejected) for auto-confirmed; same per rule for reviewed | ≥ 0.98 auto, ≥ 0.7 queue |
| **Attribution recall (proxy)** | Connector-known assets also found by discovery ÷ connector-known assets | Trend up |
| **MTTD, new asset** | `first_seen` in OpenCTEM − earliest external evidence (CT `not_before`, passive-DNS first-seen) | ≤ 24 h for CT-visible names |
| **Review queue age** | p50/p95 time `needs_review` → decision | p95 ≤ 7 d |
| **MTTR, external exposure** | Open → resolved for EASM exposures and findings, by severity | Reported (SLA policies apply) |
| **Takeover exposure count** | Open dangling/takeover exposures | → 0 |

These close three gaps the 2026-09 ctem.org comparison listed as missing:
MTTD for new external assets, drift rate and freshness. They go on the Program
Health page.

## 11. Alternatives considered

| Alternative | Why not |
|---|---|
| Run our own internet-wide scan dataset (Censys/Xpanse model) | Cost, abuse handling, legal exposure; not an OSS platform's job. Tenants can bring keys for those datasets |
| Keep candidates as assets with a state | One table, but every inventory query, count and dashboard (dozens) would have to exclude candidates. A miss shows unconfirmed hosts as "yours" and scans them. A separate table fails safe |
| Make the attribution score a multiplier in priority | A fifth competing score (RFC-017). A gate (cap at P2 until confirmed) is explainable |
| Ship puredns/shuffledns/massdns | GPL-3.0 inside an MIT SDK; the wildcard algorithm is small enough to implement in Go over dnsx |
| Run active steps from the API | Puts the control plane's IP on abuse lists, bypasses zones/politeness/egress |
| Only crt.sh for CT | Single point of failure, observed outage [45]; tiled logs need a different client [42] |
| Default nuclei settings | Runs 622 `intrusive` templates by default [66][67] |

## 12. Decisions

### 12.1 Technical decisions taken here (no owner input needed)

| # | Decision |
|---|---|
| T1 | Passive collectors on the API, anything touching a target on sensors (§6.2) |
| T2 | Candidates in their own table; promotion only through ingest (§6.4) |
| T3 | Noisy-OR confidence with negative evidence; strong-class requirement for auto-confirm; per-tenant Beta learning; tombstones; path-cascading exclusions |
| T4 | Reuse assets/relationships/exposures/findings/state history; add `asn`, `netblock`, four edge types, `easm_observations` with change-only rows |
| T5 | Attribution confidence gates priority (cap P2 below confirmed); no new score |
| T6 | Wildcard filtering implemented in Go; GPL tools only as separate executables, never linked |
| T7 | T1 nuclei flags: `-etags intrusive,default-login,fuzz,dos,bruteforce -dut` |
| T8 | DMARC evaluated against RFC 9989; TLS against TLSRef intermediate |
| T9 | Per-tenant keys and caches for licensed sources; no cross-tenant sharing |
| T10 | `findings.source = easm`; provenance on evidence/sightings (ADR-004) |

### 12.2 Owner decisions

| # | Question | Options | Recommendation |
|---|---|---|---|
| **O1** | Data sources | (a) Free sources only, platform-wide; (b) free by default + paid only with **tenant-supplied keys**; (c) the platform buys a licensed dataset (Censys/Shodan/SecurityTrails) for all tenants | **(b).** On by default: crt.sh, Cert Spotter free tier, RDAP, RIPEstat, Team Cymru, our own DNS. Paid sources BYO-key, per tenant. (c) is a licensing and cost commitment, and most free tiers forbid commercial redistribution (VirusTotal, Censys research, Netlas) [92][14][97] |
| **O2** | Run shared platform sensors for the external view? | (a) No, tenant sensors in the default zone only; (b) yes, opt-in per tenant, public targets only, from **published egress ranges** with rDNS, an info page and abuse contact; (c) yes, on by default | **(a) for OSS now, (b) for a hosted offering (P6).** (b) needs stable IPs, an abuse inbox someone reads, and a published range file kept true by an automated check. Never (c): RFC-023 D14 already rules out implicit platform use |
| **O3** | Default intrusiveness tier | T0 / **T1** / T2 for confirmed assets | **T1** for confirmed, T0 for everything else. **T2 opt-in** per scope target, needs a verified seed, a named approver and an expiry |
| **O4** | Auto-confirm threshold | Never auto-confirm; ≥ 90 with a strong rule; ≥ 75 | **≥ 90 and at least one strong rule** (verified root, seeded CIDR/ASN, connector, tenant-scanned). Everything else is reviewed |
| **O5** | Lookalike / brand monitoring | In (P6) / out | **In, passive only (T0), P6.** Generation + DNS/RDAP/CT checks; no probes of lookalike hosts; no takedown service |
| **O6** | Third-party / vendor-risk mode | In / out | **Out.** If ever in: separate register, passive public data only, no packets to vendor hosts (§7) |
| **O7** | Retention | — | Observations (changed rows) **13 months**; raw collector responses not stored (only extracted values); evidence for as long as the subject exists; rejected tombstones **12 months**; screenshots **30 days**; state history keeps its current rules (no delete under 30 days) |
| **O8** | Should results of tenant-triggered sensor scans under **unverified** roots go to the review queue instead of straight into the inventory? | Keep / change | **Keep for now** (today's behaviour, the tenant chose the target), with evidence stamped. Revisit after P2 precision data |
| **O9** | Cadence floors on shared resources | — | Tier A daily light / weekly nuclei is the fastest a tenant can set on shared sensors; own sensors are free to go faster within RFC-030 politeness |
| **O10** | Packaging | EASM in the existing `attack_surface` module / a new `easm` module | **Existing `attack_surface` module.** It already gates `/attack-surface/*` and the CT monitor; a new module would split one feature across two toggles |

### 12.3 Decisions (approved 2026-10-02)

The owner approved O1–O10 **as recommended** on 2026-10-02. These are now the
design; §12.2 keeps the options that were considered.

| # | Decision (approved 2026-10-02) |
|---|---|
| **O1** | Data sources: free sources on by default (crt.sh, Cert Spotter free tier, RDAP, RIPEstat, Team Cymru, our own DNS); paid sources (Censys, Shodan, SecurityTrails, Chaos, urlscan, HIBP, VirusTotal premium …) only with **tenant-supplied keys**, per tenant. No platform-wide licensed dataset |
| **O2** | No shared platform sensors for the external view in OSS now; tenants use their own sensor in the default (public) zone. A hosted offering may add them in P6: opt-in per tenant, public targets only, published stable egress ranges with rDNS, an information page and an abuse contact. Never on by default (RFC-023 D14) |
| **O3** | Default tier **T1 (safe-active)** for confirmed assets, T0 for all others. **T2 intrusive is opt-in** per scope target and needs a verified seed, a named approver and an expiry |
| **O4** | Auto-confirm only at confidence **≥ 90 with at least one strong rule** (verified root, seeded CIDR/ASN, connector, tenant-scanned); everything else goes to the review queue |
| **O5** | Lookalike / brand monitoring **in**, passive only (T0), in P6; no probes of lookalike hosts; no takedown service |
| **O6** | Third-party / vendor-risk mode **out**. If ever revisited: separate register, passive public data only, no packets to vendor hosts (§7) |
| **O7** | Retention: changed observation rows 13 months; raw collector responses not stored; evidence kept while its subject exists; rejected tombstones 12 months; screenshots 30 days; state history unchanged |
| **O8** | Results of tenant-triggered scans under unverified roots **keep going straight into the inventory**, with evidence stamped; revisit after P2 precision data |
| **O9** | Fastest cadence on shared sensors: Tier A daily light checks and weekly nuclei; the tenant's own sensors may go faster within RFC-030 politeness |
| **O10** | EASM ships in the existing **`attack_surface`** module; no new module |

## 13. Compatibility

- Additive migrations only:
  - new tables `easm_seeds`, `easm_candidates`, `easm_evidence`,
    `easm_observations`;
  - nullable attribution columns on `assets`;
  - new asset and relationship types (generated from
    `configs/relationship-types.yaml`).
- Legacy assets read as `confirmed` (NULL state), so nothing disappears from
  the inventory.
- New exposure event types: `dangling_cname`, `dangling_ns`,
  `subdomain_takeover`, `email_security_weak`, `lookalike_domain`. They go in
  `pkg/domain/exposure/value_objects.go` with a CHECK-constraint migration if
  the column has one.
- `/attack-surface/external` gets a 308 redirect to the new Inventory tab.
- Sensor: the new tools are additive in `full`/`platform`; `slim`/`ci`
  unchanged. Older sensors simply don't advertise them (RFC-033).

## 14. Sources

Fetched 2026-10-02 unless noted. **[W]** = marketing page or blog (weaker).
"403/502" = could not be fetched during the research; the claim relies on
secondary text and is marked in the body.

Vendors
1. Microsoft Defender EASM, *What is discovery*. https://learn.microsoft.com/en-us/azure/external-attack-surface-management/what-is-discovery
2. Microsoft Defender EASM, *Understand inventory assets*. https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-inventory-assets
3. Microsoft Defender EASM, *Use and manage discovery*. https://learn.microsoft.com/en-us/azure/external-attack-surface-management/using-and-managing-discovery
4. Microsoft Defender EASM, *Billable assets*. https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-billable-assets
5. Cortex Xpanse, *Asset attribution*. https://cortex-docs.paloaltonetworks.com/cortex-xpanse/inventory/asset-attribution.md
6. Cortex XDR ASM, *Scanning* (same engine as Xpanse: inference). https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/attack-surface-management/get-started-with-attack-surface-management/scanning.md
7. Cortex Xpanse, *Attack Surface Tests*. https://cortex-docs.paloaltonetworks.com/cortex-xpanse/attack-surface-testing/attack-surface-tests.md
8. Censys, *Opt out of data collection*. https://docs.censys.com/docs/opt-out-of-data-collection
9. Censys, *Internet scanning*. https://docs.censys.com/docs/internet-scanning
10. Censys ASM, *Seed your attack surface*. https://docs.censys.com/docs/asm-seed-your-attack-surface
11. Censys ASM, *Exclude assets*. https://docs.censys.com/docs/asm-exclude-assets
12. Censys ASM, *Inventory assets*. https://docs.censys.com/docs/asm-inventory-assets
13. Censys ASM, *Dangling DNS risks*. https://docs.censys.com/docs/asm-dangling-dns-risks
14. Censys, *Credits for Free/Starter*; *Scanning FAQ* (research access). https://docs.censys.com/docs/platform-credits-free-starter ; https://docs.censys.com/docs/scanning-faq
15. Google Threat Intelligence ASM, *Understanding seeds*. https://gtidocs.readme.io/docs/understanding-attack-surface-management-seeds
16. GTI ASM, *Scan ranges*. https://gtidocs.readme.io/docs/asm-scan-ranges
17. GTI ASM, *Opt out*. https://gtidocs.readme.io/docs/asm-opt-out
18. GTI ASM, *How issues work*. https://gtidocs.readme.io/docs/how-issues-work
19. GTI ASM, *Collections tips and tricks*. https://gtidocs.readme.io/docs/collections-tips-and-tricks
20. intrigueio GitHub organisation (intrigue-core repository returns 404). https://github.com/intrigueio
21. Tenable ASM, *Suggested domains*. https://docs.tenable.com/attack-surface-management/Content/Topics/SuggestedDomains/SuggestedDomains.htm
22. Tenable ASM, *Asset attribution*. https://docs.tenable.com/attack-surface-management/Content/Topics/Inventory/AssetAttribution.htm
23. Tenable ASM, *Licensing*; *TXT records*. https://docs.tenable.com/attack-surface-management/Content/Topics/Welcome/ASMLicensing.htm ; https://docs.tenable.com/attack-surface-management/Content/Topics/TXTRecords/TXTRecords.htm
24. Tenable ASM, *FAQ*. https://docs.tenable.com/attack-surface-management/Content/Topics/Welcome/ASM-FAQ.htm
25. Rapid7 Surface Command, *External attack surface*. https://docs.rapid7.com/surface-command/manage-external-assets/
26. Rapid7, *Sonar data* (approval-gated). https://sonardata.rapid7.com/
27. ProjectDiscovery, *Asset discovery*. https://docs.projectdiscovery.io/cloud/assets/overview
28. ProjectDiscovery, *Associated domains*. https://docs.projectdiscovery.io/cloud/assets/associated-domains
29. ProjectDiscovery, *Asset policies*. https://docs.projectdiscovery.io/cloud/assets/asset-policies
30. ProjectDiscovery, *Scan IPs*. https://docs.projectdiscovery.io/cloud/admin/scan-ips
31. Detectify, *Getting started with Surface Monitoring* **[W]**. https://detectify.com/support/solutions/articles/48001049198-getting-started-with-surface-monitoring
32. runZero, *Discovering assets* (hosted external explorer). https://help.runzero.com/docs/discovering-assets/
33. Shodan Monitor, *Network vs domain vs query*. https://help.shodan.io/shodan-monitor/network-vs-domain-vs-query
34. Shodan, *On-demand scanning*. https://help.shodan.io/the-basics/on-demand-scanning
35. Shodan, *API plans*. https://account.shodan.io/billing
36. Shodan, *Search filter reference*. https://www.shodan.io/search/filters
37. CyCognito, *Platform* **[W]**. https://www.cycognito.com/platform/
38. Hadrian **[W]**. https://hadrian.io/

Standards, data sources, tools
39. RFC 6962, Certificate Transparency. https://www.rfc-editor.org/rfc/rfc6962
40. RFC 9162, Certificate Transparency v2.0. https://www.rfc-editor.org/rfc/rfc9162
41. Google CT log list v3. https://www.gstatic.com/ct/log_list/v3/log_list.json
42. C2SP static-ct-api. https://c2sp.org/static-ct-api
43. SSLMate, Cert Spotter API pricing. https://sslmate.com/ct_search_api/
44. CertStream. https://github.com/CaliDog/certstream-server
45. crt.sh (HTTP 502 during research) and its schema. https://crt.sh/ ; https://github.com/crtsh/certwatch_db
46. Scheitle et al., "The Rise of Certificate Transparency and Its Implications on the Internet Ecosystem", IMC 2018. https://doi.org/10.1145/3278532.3278562
47. ICANN, Registration Data Policy. https://www.icann.org/resources/pages/registration-data-policy-2024-02-21-en
48. ICANN, RDAP. https://www.icann.org/rdap
49. RFC 7480, RFC 9082, RFC 9083, RFC 9224 (RDAP). https://www.rfc-editor.org/rfc/rfc7480 ; https://www.rfc-editor.org/rfc/rfc9082 ; https://www.rfc-editor.org/rfc/rfc9083 ; https://www.rfc-editor.org/rfc/rfc9224
50. CIRCL Passive DNS. https://www.circl.lu/services/passive-dns/
51. SecurityTrails, *Quotas and rate limits*. https://docs.securitytrails.com/docs/quotas-rate-limits
52. Team Cymru, IP-to-ASN mapping. https://www.team-cymru.com/ip-asn-mapping
53. RIPEstat Data API and terms. https://stat.ripe.net/docs/data_api ; https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions
54. RFC 6811, BGP prefix origin validation (and RFC 6480). https://www.rfc-editor.org/rfc/rfc6811
55. AWS Config resource types; Route 53 `ListResourceRecordSets`. https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html ; https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html
56. Azure Resource Graph. https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
57. Google Cloud Asset Inventory. https://cloud.google.com/asset-inventory/docs/overview
58. GitHub, *About secret scanning*. https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
59. dnstwist. https://github.com/elceef/dnstwist
60. Unicode UTS #39, Security Mechanisms. https://www.unicode.org/reports/tr39/
61. puredns. https://github.com/d3mondev/puredns
62. ProjectDiscovery tools (subfinder, dnsx, naabu, httpx, tlsx, katana, cdncheck, asnmap, uncover, alterx, cloudlist). https://github.com/projectdiscovery
63. httpx README. https://github.com/projectdiscovery/httpx
64. gowitness. https://github.com/sensepost/gowitness
65. wappalyzergo; webappanalyzer (Wappalyzer's original repository no longer exists). https://github.com/projectdiscovery/wappalyzergo ; https://github.com/enthec/webappanalyzer
66. nuclei-templates statistics. https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATES-STATS.md
67. nuclei-templates default ignore list. https://github.com/projectdiscovery/nuclei-templates/blob/main/.nuclei-ignore
68. nuclei, *Running*. https://docs.projectdiscovery.io/tools/nuclei/running
69. can-i-take-over-xyz. https://github.com/EdOverflow/can-i-take-over-xyz
70. Liu, Hao, Wang, "All Your DNS Records Point to Us", CCS 2016. https://doi.org/10.1145/2976749.2978387
71. Borgolte et al., "Cloud Strife: Mitigating the Security Risks of Domain-Validated Certificates", NDSS 2018. https://doi.org/10.14722/ndss.2018.23327
72. Alowaisheq et al., "Zombie Awakening: Stealthy Hijacking of Active Domains through DNS Hosting Referral", CCS 2020. https://doi.org/10.1145/3372297.3417864
73. Zhang et al., HostingChecker, POMACS 2023. https://doi.org/10.1145/3579440
74. Ma et al., stale TLS certificates, IMC 2023. https://doi.org/10.1145/3618257.3624802
75. testssl.sh. https://github.com/testssl/testssl.sh
76. TLSRef (successor to Mozilla Server Side TLS). https://docs.tlsref.org/
77. RFC 7208, SPF. https://www.rfc-editor.org/rfc/rfc7208
78. RFC 6376, DKIM. https://www.rfc-editor.org/rfc/rfc6376
79. RFC 9989, DMARC (obsoletes RFC 7489). https://www.rfc-editor.org/rfc/rfc9989
80. RFC 8461, MTA-STS; RFC 8460, TLS-RPT. https://www.rfc-editor.org/rfc/rfc8461 ; https://www.rfc-editor.org/rfc/rfc8460
81. CISA BOD 23-02 (403 during research; content from secondary knowledge). https://www.cisa.gov/news-events/directives/bod-23-02-mitigating-risk-internet-exposed-management-interfaces
82. CISA KEV data. https://github.com/cisagov/kev-data
83. FIRST EPSS. https://www.first.org/epss/
84. CERT/CC SSVC, CISA BOD 26-04 decision model; *Publicly Exposed*. https://certcc.github.io/SSVC/howto/cisa_response/ ; https://certcc.github.io/SSVC/reference/decision_points/cisa/publicly_exposed/
85. Gartner, CTEM (403 during research). https://www.gartner.com/en/articles/how-to-manage-cybersecurity-threats-not-episodes
86. Harry, Sivan-Sevilla, McDermott, county attack surfaces, Journal of Cybersecurity 2024. https://doi.org/10.1093/cybsec/tyae032
87. Durumeric, Wustrow, Halderman, "ZMap: Fast Internet-wide Scanning and Its Security Applications", USENIX Security 2013. https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/durumeric
88. Durumeric et al., "Ten Years of ZMap", IMC 2024. https://doi.org/10.1145/3646547.3689012
89. Kasama et al., scanner identification and opt-out, IEEE Access 2025. https://doi.org/10.1109/ACCESS.2025.3551691
90. Durumeric et al., "A Search Engine Backed by Internet-Wide Scanning" (Censys), CCS 2015. https://doi.org/10.1145/2810103.2813703
91. CISA Vulnerability Management scanner source IPs. https://rules.vm.cyber.dhs.gov/all.txt
92. VirusTotal, *Public vs Premium API*. https://docs.virustotal.com/reference/public-vs-premium-api
93. urlscan.io, pricing. https://urlscan.io/pricing/
94. ProjectDiscovery Chaos. https://chaos.projectdiscovery.io/
95. Have I Been Pwned, subscriptions. https://haveibeenpwned.com/Subscription
96. GreyNoise Community API. https://docs.greynoise.io/docs/using-the-greynoise-community-api
97. Netlas pricing **[W]**. https://netlas.io/pricing/
98. LeakIX plans **[W]**. https://leakix.net/plans
99. BinaryEdge transition to Coalition. https://help.coalitioninc.com/hc/en-us/articles/34383910057371-BinaryEdge-Transition-FAQ
100. OWASP Open Asset Model; asset-db; Amass. https://github.com/owasp-amass/open-asset-model ; https://github.com/owasp-amass/asset-db ; https://github.com/owasp-amass/amass
101. 18 U.S.C. §1030 (CFAA); UK Computer Misuse Act 1990; *Van Buren v. United States* (2021). General background, not legal advice. https://www.law.cornell.edu/uscode/text/18/1030 ; https://www.legislation.gov.uk/ukpga/1990/18/contents ; https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf
102. Szurdi, Christin, "Email Typosquatting", IMC 2017. https://doi.org/10.1145/3131365.3131399
103. Arturi et al., "as2org+: Enriching AS-to-Organization Mappings with PeeringDB", PAM 2023. https://doi.org/10.1007/978-3-031-28486-1_17
104. reNgine, web application reconnaissance suite (GPL-3.0), read at commit de41992 (2025-11-16). https://github.com/yogeshojha/rengine

Not verified during the research (and therefore not relied on for a design
choice): crt.sh limits; full BOD 23-02 and BOD 26-04 text on cisa.gov; Gartner's
CTEM text; scanner IPs of Microsoft, Detectify, runZero, Tenable, Rapid7;
free-tier numbers of SecurityTrails, FOFA, ZoomEye, Hunter.how, OTX; mobile-app
discovery practice.
