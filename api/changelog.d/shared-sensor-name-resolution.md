### Security: shared sensors refuse host names that resolve to internal addresses

- The shared (platform) sensor target check now resolves every host name of
  the job (through the scan-zone resolver) and refuses the job when any name
  resolves to a private, loopback, link-local (including cloud metadata),
  CGNAT or unique-local address. Before, only literal addresses and internal
  suffixes were refused. A lookup failure, a missing resolver or more than
  256 names keep the job on the organization's own sensors (fail closed).
- The resolved addresses are never shown (they may come from the platform's
  own DNS). The sensor re-checks and pins the address before it connects
  (DNS rebinding).
- Upgrade note: no action; shared sensors stay unavailable to every
  organization.
