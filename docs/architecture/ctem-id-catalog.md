# CTEM-ID Catalog

> A standardized, CVE-like reference catalog of **exposure classes** (brand
> impersonation, credential dumps, ransomware, lookalike domains, …), mirrored
> from an external JSON feed on a daily fail-open refresh. It is the exposure-side
> analogue of the KEV / EPSS threat-intel catalogs.

## What it is

`ctem_id_catalog` (migration `000208`) is **tenant-agnostic reference data** — no
`tenant_id` column, exactly like `kev_catalog` / `epss_scores`. Each row is a
CTEM-ID: a stable `ctem_id` string, a `category`, a human `title`/`description`,
optional `severity`/`source_url`/`published_at`, and the raw feed JSON. Findings
and exposures reference a CTEM-ID as a tag (an exposure taxonomy), the way a
finding references a CVE.

Categories (`pkg/domain/ctemid/category.go`): `brand_impersonation`,
`credential_dumps`, `infected_devices`, `lookalike_domains`, `ransomware`,
`source_code_exposure`, `system_exposure`, `other`.

## Refresh

- **Service:** `internal/app/ctemid/service.go` (`Service.Refresh`) fetches the
  feed (default `https://ctem.org/source.json`), bounds the body (64 MiB), and
  upserts by `ctem_id`.
- **Controller:** `internal/infra/controller/ctemid_refresh.go` runs on a
  **24-hour** cadence (`Interval()` → 24h), matching the KEV/EPSS refresh.
- **Fail-open:** a feed outage is logged and tolerated — the refresh never panics
  and never blocks ingest; the last-known catalog stays in place until the next
  successful pull.
- **SSRF-guarded egress:** the feed fetch uses `httpsec.SafeHTTPClient`, which
  refuses RFC1918 / link-local addresses even though the feed URL is public
  (defense against DNS rebinding of the configurable URL).

## API

| Endpoint | Permission |
|----------|------------|
| `GET /api/v1/ctem-ids` | `vulnerabilities:read` |

Routes: `internal/infra/http/routes/ctemid.go`; handler
`internal/infra/http/handler/ctemid_handler.go`; repository
`internal/infra/postgres/ctemid_repository.go`.

## Related

- `data-sources.md` — how exposures are discovered.
- KEV / EPSS threat-intel catalogs — the same tenant-agnostic reference-data
  pattern this mirrors.
