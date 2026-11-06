### Added: continuous coverage probes a name on the other open ports of its addresses

- A coverage batch of the HTTP probe also probes `<name>:<port>` for each other open TCP port (not 80 or 443) of the addresses each name of the batch resolves to, at most 20 per name. A virtual host, CDN or load balancer that routes by name now has its services on those ports found.
- Each `<name>:<port>` passes the same target gate as the batch (exclusions in host:port form, name ownership, scope entries and tier, zones). The port lookup is tenant-scoped; a failed lookup or gate check leaves the batch as before.
