# Certificate-Transparency (CT) Monitoring

> The first fully-built external-exposure connector: a scheduled, per-tenant
> poller that queries the **public crt.sh** Certificate-Transparency log
> aggregator (with **Cert Spotter** as the fallback) for a tenant's own domains
> and emits first-class `ExposureEvent`s — no credentials, no sensor, no
> traffic to the tenant's hosts. RFC-019; rotation, retries and fallback from
> RFC-036 P0.

## What it does

This is CTEM **Discovery** breadth ("exposure ≠ vulnerability"). For each
domain the tenant watches it queries CT and emits:

- `subdomain_discovered` — a host below the apex found in a logged certificate
  (surfaces subdomains the tenant never scanned).
- `certificate_expiring` — the host's newest certificate expires within 30 days.
- `certificate_expired` — the host's newest certificate lapsed within the last
  30 days and nothing replaced it (older lapses are retired hosts and are not
  raised).

## Which domains, and in what order

The watched set is the union of the tenant's **domain assets**, **verified
domains** (status `verified`) and **active domain scope targets** (`domain`,
`subdomain`, `email_domain`; `*.` is stripped). Names are normalised and
de-duplicated; a name whose parent is also watched is not queried separately
(the parent's `%.parent` query already returns it), except a verified child
under an unverified parent. Names without an ICANN public suffix (`.local`,
`.internal`, `.test`, bare `co.uk`) are dropped: they cannot have public
certificates.

Approved scope exclusions apply (RFC-042 F16): a watched name that matches
one is not queried, and a host that matches one gets no exposure (no
`subdomain_discovered`, no certificate expiry). A failed exclusion lookup
skips the tenant's sweep for that run.

Each run queries at most `CERT_MONITOR_MAX_DOMAINS_PER_RUN` (default 50)
domains per tenant, picked from `ct_monitor_state` (migration 000266):

1. a domain in failure back-off waits (12 h, 24 h, 48 h … 7 days);
2. a domain queried successfully within 5/6 of the interval is not due, so an
   API restart does not re-query everything;
3. the rest are taken never-succeeded first, then oldest success, then oldest
   attempt. With 120 domains and the default cap, every domain is queried
   within three daily runs.

A tenant's sweep also stops after 30 minutes; the domains it did not reach
lead the next run. A per-tenant controller lease (`ct_monitor:<tenant>`, RFC-046 P1.8) keeps two API replicas from
sweeping the same tenant at once.

## From CT name to inventory asset

After the exposures are written, names fit for the inventory are promoted
through the normal ingest path (`internal/app/certmonitor/promote.go`), so
identity resolution, state history and the exposure bridge apply as for any
other source. A name is promoted when it is named exactly on a certificate
(not only through a wildcard) whose newest `not_after` is no more than 90 days
ago. At most 500 new assets per tenant per run, verified-root names first.

| Found under | Evidence rule | Attribution |
|---|---|---|
| a verified domain | `fqdn_under_verified_root` (0.99, strong) | `confirmed` (O4: strong rule and ≥ 90) |
| a domain asset or scope target the tenant did not verify | `fqdn_under_asserted_root` (0.85, medium) | `needs_review` |

Promoted assets are `subdomain` assets with `discovery_source =
cert_transparency` and `discovery_tool` = the CT source (`crt.sh` or
`certspotter`); `discovered_at` is the earliest `not_before` CT shows, the
earliest external evidence. A name that is already an asset is not
re-ingested: it gets the evidence row only and keeps its standing (an asset
with no attribution record is a legacy, confirmed asset).

Attribution lives in `asset_attributions` and `easm_evidence` (migration
000324); see [easm.md](easm.md#4-attribution). Scans skip asset-group members
that are not confirmed, so nothing found passively under an unverified
domain is touched by a sensor until a person confirms it (`PUT
/api/v1/assets/{id}/attribution`, audited).

## Rejected names, identity and linking

Since research/22 P0-9 (bug 22c B2):

- **Promotion runs first**, then the exposures are built, so a CT exposure
  links to **the host's own asset** when one exists (a promoted or older
  subdomain asset), else to its nearest domain asset, else to the root's.
  Stored rows linked elsewhere (or to nothing, from a seed-only period) are
  moved onto that asset (`ExposureRepository.RelinkExposures`, tenant's own
  assets only).
- **Identity does not depend on the link.** A CT exposure's fingerprint is
  tenant, type, title and host (`certmonitor.ctFingerprint`), so linking or
  relinking never creates a second row. Migration `001018` re-keyed the
  stored rows and resolved the duplicates it collapsed (reversible: the old
  fingerprints and states are kept in `easm_ct_rekey_001018`).
- **Rejected names stay quiet.** A host that is rejected (an asset whose
  attribution is `rejected`, or a live tombstone), or that sits under one,
  produces no CT exposure (`hosts_rejected` in the sweep log). When a person
  rejects a name (review queue or `PUT /assets/{id}/attribution`), its open
  CT and DNS-check exposures and those of names under it are resolved with
  the note "marked not ours (rejected)". Un-rejecting does not reopen them;
  the next sweeps raise what is still true.

## Sources, retries and fallback

| Step | Behaviour |
|---|---|
| crt.sh | `GET /?q=%.<domain>&output=json&deduplicate=Y`; up to 3 attempts on network errors, 408, 429 and 5xx, waiting 2 s → 30 s with jitter or the server's `Retry-After` (≤ 60 s). A 50 s response-header timeout (crt.sh is slow for busy domains) |
| Cert Spotter | Used when crt.sh still fails: `GET /v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer`, unauthenticated free tier, up to 10 pages. A 429 stops Cert Spotter for the rest of that sweep. It lists only unexpired certificates, so it never yields `certificate_expired` |
| Both fail | The failure and error are stored on the domain's state row and it backs off |

Configuration: `CERT_MONITOR_ENABLED` (default true), `CERT_MONITOR_INTERVAL`
(24h), `CERT_MONITOR_FEED_URL` (`https://crt.sh`),
`CERT_MONITOR_CERTSPOTTER_URL` (`https://api.certspotter.com`, `off`
disables), `CERT_MONITOR_MAX_DOMAINS_PER_RUN` (50).
Since research/22 P0-11 `CERT_MONITOR_INTERVAL` is the platform default
interval: the controller ticks hourly, a domain is re-queried once its window
passed, and a tenant may set its own interval (6 h to 168 h) or turn the
monitor off (`/api/v1/easm/settings`; then its names are not sent to crt.sh
or Cert Spotter).

Data-source note (RFC-036 O1): only the watched domain names are sent to crt.sh
and Cert Spotter. Both are free public services; heavy commercial use of
Cert Spotter needs an SSLMate key, which belongs to the per-tenant paid
sources of P5.

Source tag on everything emitted: `cert_transparency`
(`internal/app/certmonitor/service.go`, `Source`).

It complements the agent-side subfinder recon (which enumerates subdomains
on demand during a scan job): CT monitoring runs continuously server-side and,
crucially, surfaces cert-expiry exposures and certs issued for domains the tenant
never scanned.

## Safety & isolation

- **SSRF-guarded egress:** every CT query dials through
  `httpsec.SafeDialContext` — it refuses RFC1918 / link-local / metadata
  addresses even though the sources are public (defense against DNS rebinding
  of the configurable URLs). Bodies are capped at 48 MiB and the sweep waits
  1 s between domains.
- **Untrusted names:** a CT name is kept only if it is a syntactically valid
  hostname at or below the queried domain; markup, control characters and
  over-long labels are dropped before they reach an exposure.
- **Tenant isolation:** the tenant is taken from the **asset being queried, never
  from the CT response**; every emitted exposure is stamped with that tenant.
- **Fail-open:** a failure on one domain or one tenant is logged and skipped — it
  never aborts the sweep.

## Wiring

- **Service:** `internal/app/certmonitor/service.go` (crt.sh client + parser +
  exposure emission).
- **Controller:** `internal/infra/controller/cert_monitor_refresh.go` — a
  background sweep across all active tenants on a **24-hour** default cadence (CT
  data changes on the order of days). Each tenant is handled serially; a
  per-tenant failure is skipped fail-open. Tenants with the `attack_surface`
  module disabled are skipped.
- **Rotation state:** `internal/infra/postgres/ct_monitor_state_repository.go`
  (table `ct_monitor_state`); sources and retries in
  `internal/app/certmonitor/ctlog.go`, selection in `selection.go`.
- **Assurance:** use cases, edge cases and the threat model with their tests
  are in [RFC-036 appendix](../rfcs/RFC-036-appendix-assurance.md).

## Not yet built (RFC-019 Phase 2)

Lookalike / typosquat detection is scoped but not implemented (RFC-036 P6,
passive only per O5). Promotion of discovered subdomains into assets is built
(see above).

## Related

- `data-sources.md` — the exposure-discovery model this plugs into.
- RFC-019 (`docs/rfcs/RFC-019-certificate-transparency-discovery.md`).
- [easm.md](easm.md) and RFC-036: where CT fits in the EASM pipeline.
