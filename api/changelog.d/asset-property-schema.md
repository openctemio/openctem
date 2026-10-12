### Behaviour change: one key per asset property, from the type registry

- The asset type registry (`api/configs/asset-types.yaml`, served by `GET /api/v1/asset-types` as `properties` and `common_properties`) declares every property key once: English and Vietnamese labels, display format, synonyms and, for keys such as `port`, the classes that may hold them (RFC-042 §6.3.9).
- An asset's addresses are stored only as `ip_addresses`. Ingest, `POST`/`PUT /api/v1/assets` and CSV import fold `ip`, `ips`, a plain `ip_address` string, `resolved_ip`, `resolved_ips` and `addresses` into it (and `nameserver`, `technology`, `san` into their plural keys). The domain DNS flattening writes `ip_addresses` instead of `resolved_ip`/`resolved_ips`.
- A port reported on a domain, subdomain, host or IP address is stored as that asset's `host:port/proto` open-port service with an `exposes` edge, not as a property of the domain. REST and import refuse such a key with 400.
- A domain's addresses also become `resolves_to` edges to IP assets for every report that may change the domain; a repeated sighting refreshes the edge's `last_verified`.
- Scope exclusions, IP correlation, relationship inference and the IP lookups read addresses through one helper, under the canonical key and every synonym.
