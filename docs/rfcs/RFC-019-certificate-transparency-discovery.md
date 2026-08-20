# RFC-019 — Certificate-Transparency (CT) exposure discovery

- Status: **Implemented (Phase 1)** — the buildable core ships in this PR: crt.sh client + parser, per-tenant scheduled controller, and two exposure types emitted. Phase 2 (lookalike/typosquat detection, asset promotion) is scoped but **not** built.
- Area: CTEM Discovery — external-exposure connectors, external attack surface.
- Related: RFC-018 (identity exposure discovery — the sibling connector; it shipped only the *vocabulary*), `internal/app/ctemid` (the public-JSON-feed refresh pattern this mirrors), `internal/app/exposurebridge` (the exposure projection this joins), `pkg/httpsec` (SSRF guard).

## 1. Goal

Give OpenCTEM its **first fully-buildable external-exposure connector**: a
passive, **public-data**, no-credentials, no-agent, no-consent source that
monitors the tenant's own domains in the public **Certificate Transparency**
logs (via the crt.sh aggregator) and records what it finds as first-class
`ExposureEvent`s. This is CTEM Discovery breadth — *exposure ≠ vulnerability* —
and unlike the identity connector (RFC-018) it needs **no** admin consent and
**no** new credential grant: CT logs are world-readable.

## 2. What CT adds over the recon we already have (the delta — honest)

The agent already runs **subfinder** (`agent/internal/executor/recon.go`), and
Certificate Transparency is *one of subfinder's own sources*. So subdomain
discovery **overlaps** with existing recon. CT monitoring is still worth
building because it is materially different in shape and gives net-new value:

| | Agent subfinder recon | CT monitoring (this connector) |
|---|---|---|
| Trigger | On-demand, inside a scan **job** dispatched to an agent | Continuous, **server-side**, no agent, no job |
| Availability | Needs a live agent + a recon scan configured | Always on for any tenant with a domain asset |
| Subdomain enum | Yes (CT is one source among many) | Yes (CT only) — **overlaps** |
| **Cert-expiry exposure** | **No** — recon enumerates hosts, it does not track certificate `not_after` | **Yes — the clear net-new**: `certificate_expiring` before TLS lapses |
| Coverage of un-scanned domains | Only domains you actively scan | Every domain asset, even ones never scanned |

**Honest scope call:** the genuinely net-new value is **cert-expiry monitoring**
and always-on coverage. `subdomain_discovered` from CT is emitted too (it lands
in the same Exposure Register and is deduped by fingerprint), but it is
**not** unique to this connector — it re-surfaces, server-side and continuously,
a subset of what an agent recon scan would find.

## 3. Exposure types emitted

Both already exist in the exposure vocabulary (`pkg/domain/exposure/value_objects.go`),
so **no migration** is needed:

- `subdomain_discovered` (severity `info`) — a host under a monitored domain seen
  in a CT certificate. Apex domain and out-of-scope names are excluded.
- `certificate_expiring` (severity by days-left: ≤7 high, ≤14 medium, else low) —
  a host whose **most-recent** CT certificate expires within 30 days.

Expiry uses the **MAX `not_after` per host**, so a long tail of historical/expired
certs never raises a false "expiring" alert when the host has a current cert; a
host whose newest cert already lapsed is treated as *expired, not expiring* and
dropped (avoids flooding on long-dead hosts).

Dedupe: the exposure fingerprint whitelist includes `domain`, and titles are
stable per (type, host), so a daily re-poll upserts the same rows (refreshing
`days_remaining`/severity, preserving any user-set state) rather than duplicating.

## 4. Safety

- **SSRF-guarded**: the outbound crt.sh call uses `httpsec.SafeHTTPClient`, which
  refuses RFC1918/link-local/loopback even though crt.sh is public — defense
  against DNS-rebinding of the operator-configurable feed URL (`CERT_MONITOR_FEED_URL`).
- **Rate-limited**: a politeness delay between per-domain queries; bounded at
  ≤50 domains/tenant/run (overflow logged, deferred to the next sweep).
- **Body-bounded**: crt.sh responses are `io.LimitReader`-capped.
- **Tenant-isolated**: the tenant is taken from the queried domain **asset**,
  never from the CT response; every emitted exposure is stamped with that tenant.
- **Fail-open**: a crt.sh outage on one domain or one tenant is logged and
  skipped; it never aborts the sweep or blocks ingest.

## 5. Where it lives

- `internal/app/certmonitor/service.go` — crt.sh client + pure parser +
  `collectDiscoveries` (pure) + exposure emission.
- `internal/infra/controller/cert_monitor_refresh.go` — daily per-active-tenant
  controller (mirrors `threat-model-refresh` / `ctem-id-refresh`).
- Config: `CERT_MONITOR_ENABLED` (default true), `CERT_MONITOR_FEED_URL`
  (default `https://crt.sh`), `CERT_MONITOR_INTERVAL` (default 24h).

## 6. Not built (Phase 2 — deliberately deferred)

- **Lookalike / typosquat detection** — flagging brand-adjacent domains in CT
  (e.g. `acme-login.com` for `acme.com`). This needs a similarity search over CT,
  is noisy, and maps to a CTEM-ID `lookalike domains` category; deferred.
- **Asset promotion** — turning a discovered subdomain into a first-class asset
  record. This connector only emits exposures; asset creation stays owned by the
  ingest/asset pipeline to avoid a second, divergent asset-creation path.
- `certificate_expired` emission for already-lapsed certs (dropped today to avoid
  flooding on historical certs).
