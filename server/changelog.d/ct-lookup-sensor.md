### Added: Certificate Transparency monitoring through platform sensors (lookup.ct@1)

- The CT sweep, certificate-expiry and subdomain exposures from CT are back, without the platform contacting a CT source: each watched domain is a lookup job that a platform-owned, instance-scope sensor reporting `lookup.ct@1` answers (sensor `SENSOR_CT_LOOKUP`, on by default on a shared sensor with a pinned job-signing key; the bundled sensor once it runs a sensor version with CT lookups). The sensor queries crt.sh, then Cert Spotter, and returns certificate records with a status per source.
- `GET /api/v1/easm/settings` reports `ct_available: true` while such a sensor is connected and a job signer is configured, checked per request; otherwise `ct_unavailable_reason: needs_platform_sensor` as before. A sensor connected later turns monitoring on without a restart. Older sensors keep working; CT stays off with them.
- New sensor routes `GET /api/v2/sensor/lookups/next` and `POST /api/v2/sensor/lookups/{id}/done`, a stage catalog entry `lookup.ct` (cross-cutting, T0, tool `ctlog`), and migration `20261112040823_sensor_lookup_jobs` (open questions only, deleted once answered).

### Security: lookup jobs are bound to one organization and to platform sensors

- A lookup job is created for the swept organization and its answer read back by (organization, job id); only an active instance-scope sensor reporting the capability is offered or may answer it (an organization's sensor gets 403); a job is answered once, by the sensor that claimed it. The job signer signs a `lookup` statement only for the instance scope, the `ctlog` tool and one canonical root domain, and the scope ledger's exclusions apply.
- The platform does not trust the answer: it is decoded strictly, bounded (8 MiB), and every name outside the domain the platform asked about is dropped before it reaches an exposure; a wildcard-only name never becomes a host.

### Removed: CERT_MONITOR_FEED_URL, CERT_MONITOR_CERTSPOTTER_URL, CERT_MONITOR_CERTSPOTTER_KEY

- The platform no longer queries CT sources, so these settings are gone; the API refuses to start while one is set and names the sensor settings instead: `SENSOR_CT_CRTSH_URL`, `SENSOR_CT_CERTSPOTTER_URL`, `SENSOR_CT_CERTSPOTTER_KEY` on the platform sensor. Upgrade note: unset them before upgrading (no install template set them).
