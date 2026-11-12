# Certificate-Transparency (CT) Monitoring

> A scheduled, per-tenant poller that queries the **public crt.sh**
> Certificate-Transparency log aggregator (with **Cert Spotter** as the
> fallback) for a tenant's own domains and emits first-class `ExposureEvent`s,
> with no credentials and no traffic to the tenant's hosts. RFC-019; rotation,
> retries and fallback from RFC-036 P0.
>
> **Zero platform egress.** The platform makes no CT request itself. Each
> domain is a **lookup job** (capability `lookup.ct@1`, command type
> `lookup`) that a platform-owned, instance-scope sensor answers for one
> organization: the sensor queries crt.sh, then Cert Spotter, and returns a
> typed answer (contract package `ctlookup`: certificate records and
> per-source status). The sweep runs only while such a sensor is connected
> (active, seen in the last 5 minutes, reporting `lookup.ct@1`) and a job
> signer is configured; otherwise the EASM settings report
> `ct_available: false` with `ct_unavailable_reason: needs_platform_sensor`
> and the monitoring card says so. Availability is checked per request and per
> sweep, so connecting a sensor turns monitoring on without a restart. A
> platform sensor serves CT lookups by default when it is a shared sensor with
> a pinned job-signing key (sensor setting `SENSOR_CT_LOOKUP`, sdk-go
> `pkg/ctlog`; the bundled sensor of a compose, Helm or Ansible install is
> one). Older sensors do not report the capability, so the platform works with
> them and keeps CT off. Certificate Transparency **names** also reach the
> inventory through the passive subdomain discovery (`discover.subdomains`)
> that runs on sensors (subfinder's crt.sh and Cert Spotter sources). The
> lookalike certificate count (RFC-083) does not use lookup jobs yet and stays
> off.

## What it does

This is CTEM **Discovery** breadth ("exposure ≠ vulnerability"). For each
domain the tenant watches it queries CT and emits:

- `subdomain_discovered` — a host below the apex found in a logged certificate
  (surfaces subdomains the tenant never scanned).
- `certificate_expiring` — the host's newest certificate expires within 30 days.
- `certificate_expired` — the host's newest certificate lapsed within the last
  30 days and nothing replaced it (older lapses are retired hosts and are not
  raised).

## Flow

```mermaid
sequenceDiagram
  autonumber
  participant CT as controller cert-monitor, hourly tick
  box API
  participant S as certmonitor.Service
  participant DB as Postgres, tenant-scoped
  participant P as promote.go, ingest path
  end
  participant J as sensor_lookup_jobs
  end
  box Platform sensor (instance scope, lookup.ct@1)
  participant N as sdk-go pkg/ctlog
  end
  participant A as crt.sh, then Cert Spotter
  CT->>S: tenant run, attack_surface module on, ct_enabled read (unreadable: skip)
  S->>S: a platform sensor serves lookup.ct@1? (no: nothing queried, no state change)
  S->>DB: lease ct_monitor:tenant
  S->>DB: gatherRoots: approved domain assets, verified domains, discovery-on domain or subdomain entries
  S->>DB: exclusions (failed lookup: skip the tenant), ct_monitor_state: due names, 50 max
  loop each due name, 1 s apart, 30 min budget
    S->>J: lookup job for this tenant and name, wait up to 120 s
    N->>J: claim (GET /api/v2/sensor/lookups/next), statement signed for the tenant, instance scope, this sensor
    N->>A: q=%.name (3 attempts, pace, Retry-After), then issuances (10 pages)
    N->>J: answer (POST /api/v2/sensor/lookups/{id}/done)
    J->>S: answer, read by (tenant, job id); job row deleted
    S->>S: ctlookup.Validate against the name asked: drop names outside it
    alt no source ok, timeout or a broken answer
      S->>DB: failure, back off 12 h doubling to 7 d (or the source's Retry-After)
    else answer
      S->>S: keep valid host names at or below the name, drop excluded and rejected
    end
  end
  S->>P: promote names on a cert not lapsed over 90 days, 500 new per run, evidence rows
  S->>DB: subdomain_discovered, certificate_expiring, certificate_expired, relink to host assets
```

## Which domains, and in what order

The watched set (`gatherRoots`, `service.go`) is the union of the tenant's
**approved domain assets** (attribution confirmed, dependency, monitor only
or no record: a domain a scan or sensor found and nobody approved never
widens the watch list), **verified domains** (status `verified`) and
**active scope targets with discovery on** of type `domain` or `subdomain`
(`*.` is stripped; one-off entries never discover). Names are normalised and
de-duplicated; a name whose parent is also watched is not queried separately
(the parent's `%.parent` query already returns it), except a verified child
under an unverified parent. Names without an ICANN public suffix (`.local`,
`.internal`, `.test`, bare `co.uk`) are dropped: they cannot have public
certificates.

Approved scope exclusions apply (RFC-042 F16): a watched name that matches
one is not queried, and a host that matches one gets no exposure (no
`subdomain_discovered`, no certificate expiry). A failed exclusion lookup
skips the tenant's sweep for that run.

An exclusion of a **dedicated address** also reaches the names that resolve
to it: an existing name whose address properties or `resolves_to` relations
hit an excluded address is not promoted again and gets no CT evidence (the
same rule as certificate SAN promotion and scan dispatch). Addresses of a
provider's shared front end never propagate (`scope.PropagatingAddresses`),
so a name behind a CDN edge is still promoted. A new name has no known
address yet; ingest checks its name again before creating it. A failed
address lookup promotes nothing for that run (fail closed); the sweep's
exposures are still written.

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
| an active, permanent scope target or a root-domain seed (not excluded, not tombstoned, not under a rejected name) | also `matches_scope_target` (0.99, strong; RFC-054 §4.3) | `confirmed` |

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

Current behaviour:

- **Promotion runs first**, then the exposures are built, so a CT exposure
  links to **the host's own asset** when one exists (a promoted or older
  subdomain asset), else to its nearest domain asset, else to the root's.
  Stored rows linked elsewhere (or to nothing, from a seed-only period) are
  moved onto that asset (`ExposureRepository.RelinkExposures`, tenant's own
  assets only).
- **Identity does not depend on the link.** A CT exposure's fingerprint is
  tenant, type, title and host (`certmonitor.ctFingerprint`), so linking or
  relinking never creates a second row. Migration `001018` re-keyed the
  stored rows and resolved the duplicates it collapsed.
- **Rejected names stay quiet.** A host that is rejected (an asset whose
  attribution is `rejected`, or a live tombstone), or that sits under one,
  produces no CT exposure (`hosts_rejected` in the sweep log). When a person
  rejects a name (review queue or `PUT /assets/{id}/attribution`), its open
  CT and DNS-check exposures and those of names under it are resolved with
  the note "marked not ours (rejected)". Un-rejecting does not reopen them;
  the next sweeps raise what is still true.

## Sources, retries and fallback

The sources are queried by the platform sensor (sdk-go `pkg/ctlog`), never by
the platform:

| Step | Behaviour |
|---|---|
| crt.sh | `GET /?q=%.<domain>&output=json&deduplicate=Y`; up to 3 attempts on network errors, 408 and 5xx, waiting 2 s to 30 s with jitter or the server's `Retry-After` (at most 60 s). A 429 is reported `rate_limited` at once |
| Cert Spotter | Used when crt.sh is not ok: `GET /v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer`, up to 10 pages, with `Authorization: Bearer <key>` when the sensor has a key (`SENSOR_CT_CERTSPOTTER_KEY`, sent only to the Cert Spotter host), else the unauthenticated tier. It lists only unexpired certificates, so it never yields `certificate_expired` |
| Pace and cache | One request per second per source for the whole sensor, a cool-down after a 429 or `Retry-After` (a source cooling down for over 60 s is reported `rate_limited` without a request), a 48 MiB body cap (over it: `too_large`, nothing used), and a 20 h answer cache per (organization, domain) that is never shared across organizations |
| Answer | `{records, source_status}`: a source failure is a status (`rate_limited`, `unavailable`, `too_large`, with `retry_after_s`), never a failed job |
| Both fail | The platform stores the failure on the domain's state row; it backs off 12 h doubling to 7 d, or longer when a source asked for it |

Configuration on the platform: `CERT_MONITOR_ENABLED` (default true),
`CERT_MONITOR_INTERVAL` (24h), `CERT_MONITOR_MAX_DOMAINS_PER_RUN` (50).
`CERT_MONITOR_INTERVAL` is the platform default interval: the controller
ticks hourly, a domain is re-queried once its window passed, and a tenant may
set its own interval (6 h to 168 h) or turn the monitor off
(`/api/v1/easm/settings`; then its names are not sent to crt.sh or Cert
Spotter). The source settings are the platform sensor's: `SENSOR_CT_LOOKUP`,
`SENSOR_CT_CRTSH_URL`, `SENSOR_CT_CERTSPOTTER_URL` (`off` disables the
fallback) and `SENSOR_CT_CERTSPOTTER_KEY` (or `_FILE`). The former platform
settings `CERT_MONITOR_FEED_URL`, `CERT_MONITOR_CERTSPOTTER_URL` and
`CERT_MONITOR_CERTSPOTTER_KEY` are removed: the API refuses to start while one
is set and names the sensor setting instead.

Data-source note (RFC-036 O1): only the watched domain names are sent to crt.sh
and Cert Spotter, and only from a platform sensor. crt.sh publishes no terms of
use, and Cert Spotter's unauthenticated tier is for personal use: the operator
of the platform sensor answers for the sources' terms, and a commercial
service gives its sensors a Cert Spotter key.

Source tag on everything emitted: `cert_transparency`
(`internal/app/certmonitor/service.go`, `Source`).

It complements the sensor-side subfinder recon (which enumerates subdomains
on demand during a scan job): CT monitoring runs continuously server-side and,
crucially, surfaces cert-expiry exposures and certs issued for domains the tenant
never scanned.

## Safety & isolation

- **No platform egress:** the service holds no HTTP client or dialer
  (`TestNoOutboundClientInTheService`); every query is a lookup job a
  platform sensor answers. The sweep waits 1 s between domains.
- **Only platform sensors are asked:** a lookup job is offered and accepted
  only from an active instance-scope sensor with no organization that reports
  `lookup.ct@1` (`internal/app/lookupjob`); an organization's sensor gets 403
  on both routes. The job signer signs a `lookup` statement only for the
  instance scope, the `ctlog` tool and one canonical root domain
  (`internal/signer/lookup.go`), and the scope ledger's exclusions apply.
- **Mutual distrust:** the answer is decoded strictly (unknown fields refused,
  8 MiB cap) and passed through `ctlookup.Validate` against the domain the
  platform asked about: a name outside it is dropped and counted, a leading
  wildcard label is kept (a wildcard certificate proves no host), an unknown
  source or state refuses the whole answer. A job is answered once, only by
  the sensor that claimed it.
- **Untrusted names:** a CT name is kept only if it is a syntactically valid
  hostname at or below the queried domain; markup, control characters and
  over-long labels are dropped before they reach an exposure.
- **Tenant isolation:** the tenant is taken from the **asset being queried, never
  from the CT response or the sensor**; the lookup job is created for that
  tenant, its answer is read back by (tenant, job id), and every emitted
  exposure is stamped with that tenant.
- **Fail-open:** a failure on one domain or one tenant is logged and skipped — it
  never aborts the sweep.

## Wiring

- **Service:** `internal/app/certmonitor/service.go` (selection, discovery and
  exposure emission); the CT source in `ctlog.go` (`CTSource`, `SensorSource`).
- **Lookup jobs:** `internal/app/lookupjob` (ask, claim, sign, answer),
  `internal/infra/postgres/lookup_job_repository.go` (table
  `sensor_lookup_jobs`, migration `20261112040823_sensor_lookup_jobs`: open
  questions only, deleted once answered, purged after a day), sensor routes
  `GET /api/v2/sensor/lookups/next` and `POST /api/v2/sensor/lookups/{id}/done`
  (`internal/infra/http/handler/lookup_job_handler.go`), stage catalog entry
  `lookup.ct` (cross-cutting, T0, tool `ctlog`).
- **Controller:** `internal/infra/controller/cert_monitor_refresh.go` — a
  background sweep across all active tenants on a **24-hour** default cadence (CT
  data changes on the order of days). Each tenant is handled serially; a
  per-tenant failure is skipped fail-open. Tenants with the `attack_surface`
  module disabled are skipped.
- **Rotation state:** `internal/infra/postgres/ct_monitor_state_repository.go`
  (table `ct_monitor_state`); selection in `selection.go`.
- **Assurance:** use cases, edge cases and the threat model with their tests
  are in [RFC-036 appendix](../rfcs/RFC-036-appendix-assurance.md).

## Lookalike domains

Lookalike detection is built, passive only (O5): see
[easm.md](easm.md#4l-lookalike-domains-built) and RFC-083. Promotion of
discovered subdomains into assets is built (see above).

## Related

- `data-sources.md` — the exposure-discovery model this plugs into.
- RFC-019 (`docs/rfcs/RFC-019-certificate-transparency-discovery.md`).
- [easm.md](easm.md) and RFC-036: where CT fits in EASM discovery.
