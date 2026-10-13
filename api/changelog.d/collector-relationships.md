### Added: collector placement is stored as asset relationships

- A report's typed `relationships` (CTIS) become asset relationships when the registry allows the pair: `hosted_by` is stored as `runs_on` (a virtual machine on its hypervisor host, a service on a host) or, for an address, as the host `contains` the address; `subdomain_of` is stored parent first as `contains`; `resolves_to`, `cname_of`, `exposes` and `serves_certificate` keep their type.
- A virtual machine whose report names its hypervisor host (`esxi_host`, sent by the vCenter collector) gets a `runs_on` edge to that host, and a reported host gets a `contains` edge to each existing address asset of its `ip_addresses` (at most 32; addresses are never created from a host's properties).
- Both ends are always assets of the reporting tenant, an edge is added only when the report may change its source asset (an unsolicited report adds none to an existing asset), and writing an edge again only refreshes when it was last seen.
- The relationship registry now allows `host runs_on host` and `host contains ip_address`.
