### Fixed: an HTTP probe creates web origin assets

- The recon converter names an `http_service` by its bare host. Ingest used
  that name, which is the name of the subdomain or address the origin runs on,
  so the probe's result was folded into that row and no web origin asset was
  ever created: crawling, templates and DAST had no web target. Ingest now
  identifies an `http_service` by its URL (`https://app.example.com`,
  `http://203.0.113.7:8080`), so every probed origin is its own asset and the
  subdomain or address keeps its type.
- Existing inventories: the next HTTP probe creates the missing origins. No
  backfill: the folded observations carry no port, so an origin rebuilt from
  them could be wrong.
