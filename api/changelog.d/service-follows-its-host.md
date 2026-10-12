### Fixed: a service follows its host in scope, review and dispatch

- A service is stored as `host:port:proto` (for example
  `example.co.uk:443:tcp`), but the scope code read host names with a
  `host:port` parser that fails on three parts. So a service under a
  permanent scope entry stayed in the review queue instead of joining the
  inventory (RFC-054 S4), and the scope authority did not see its host.
- One parser, `asset.SplitServiceName` / `asset.HostOf`, now reads every form
  (`host:port:proto`, `host:port/proto`, `host:port`, `[v6]:port/proto`,
  `[v6]:port:proto` and the stored `v6:port:proto`) and is used by the scope
  join, the active-probe authority and ownership gate, exclusions, internal
  target detection, the scan stamper, retests, ingest and sensor grants. A
  network (`203.0.113.0/24`) is never cut to its first address.
- A service on an IP address still joins only through an IP, range or CIDR
  scope entry: a name grant never becomes an IP grant.
- The stored form is unchanged (`host:port:proto`, written by the inventory
  normalizer), so no data migration is needed. The scope-join run at start-up
  confirms the services left in review.
