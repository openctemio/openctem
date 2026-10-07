### Security: the platform deny list, private-target and zone checks read service names

- A service is stored as `host:port:proto` and reported as
  `host:port/proto`. The platform deny list (`SCOPE_DENY_EXTRA`, metadata and
  link-local addresses, government suffixes) did not see the address of a
  service in either form, so `169.254.169.254:80:tcp` or a service on a
  deny-listed range passed the dispatch check. The private-target check read
  `10.0.0.5:22:tcp` as public, and scan-zone routing could not route it to its
  zone.
- These checks, and host leases, hop routing, target
  validation and the scope coverage count, now read
  every service form through the one parser (`asset.SplitServiceName` /
  `asset.HostOf`). A service on a private address
  routes only to the zone that holds the address, and is refused outside every
  zone.
