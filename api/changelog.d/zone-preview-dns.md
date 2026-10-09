### Security: scan-zone preview no longer resolves names a tenant may not scan

- `POST /api/v1/scan-zones/preview` resolved every target hostname with the platform's own DNS resolver, without checking the target first, and returned the answers. On a cloud deployment, the platform's resolver knows internal names, for example private hosted zones and cluster DNS. So any member with `scan_zones:read` could map the platform's internal network. Private answers also appeared in the reason text.
- The preview now runs the same act-scope check as scan creation first. A target with no scope entry covering it, or outside the member's data scope, is refused without any lookup.
- An answer is shown only when it is public, or when it lies inside the zone the target routed to. Reasons never quote an address.
- **Behaviour change:** scan-zone routing resolves hostnames with `SCAN_ZONE_RESOLVER`, either `system` or `host[:port]`. When it is unset, self-service installs (`TENANT_CREATION_MODE=self_service`) use the public resolver `1.1.1.1:53`, and every other install keeps the platform's own resolver.
- **Upgrade note:** on a self-service install, the API must be able to reach the configured resolver on port 53. Hostnames that resolve only through the platform's internal DNS no longer route to a zone there.
