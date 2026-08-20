# Certificate-Transparency (CT) Monitoring

> The first fully-built external-exposure connector: a scheduled, per-tenant
> poller that queries the **public crt.sh** Certificate-Transparency log
> aggregator for a tenant's own registered domains and emits first-class
> `ExposureEvent`s — no credentials, no agent, no customer consent. RFC-019.

## What it does

This is CTEM **Discovery** breadth ("exposure ≠ vulnerability"). For each of a
tenant's domain assets it queries crt.sh and emits:

- `subdomain_discovered` — a host below the apex found in a logged certificate
  (surfaces subdomains the tenant never scanned).
- `certificate_expiring` — a certificate approaching expiry.

Source tag on everything emitted: `cert_transparency`
(`internal/app/certmonitor/service.go`, `Source`).

It complements the agent-side subfinder recon (which enumerates subdomains
on demand during a scan job): CT monitoring runs continuously server-side and,
crucially, surfaces cert-expiry exposures and certs issued for domains the tenant
never scanned.

## Safety & isolation

- **SSRF-guarded egress:** the crt.sh query goes through
  `httpsec.SafeHTTPClient` — it refuses RFC1918 / link-local addresses even
  though crt.sh is public (defense against DNS rebinding of the configurable feed
  URL). The response body is bounded and the sweep is politeness-rate-limited
  between domains.
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
  per-tenant failure is skipped fail-open.

## Not yet built (RFC-019 Phase 2)

Lookalike / typosquat detection and promoting a discovered subdomain into a
first-class asset are scoped but not implemented.

## Related

- `data-sources.md` — the exposure-discovery model this plugs into.
- RFC-019 (`docs/rfcs/RFC-019-certificate-transparency-discovery.md`).
