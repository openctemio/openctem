### Added: asset data freshness per attribute class

- Every ingest now records, per asset, when each enrichable attribute class
  was last observed and by which tool: DNS (`resolve.dns`), registration
  (`lookup.rdap`), network owner (`lookup.asn`), HTTP and TLS
  (`probe.http`), ports (`scan.ports`). An older report never moves the
  clock back (migration `001980_asset_freshness`, RFC-075).
- `GET /api/v1/assets/{id}/freshness` (`assets:read`, data scope of the
  asset) returns each class with its TTL (halved for critical, high or
  internet-facing assets) and its state: live, stale, dead or never.
- `GET /api/v1/assets?freshness=stale|never` lists assets with a class past
  its TTL, or with a passive class that applies and was never observed.
