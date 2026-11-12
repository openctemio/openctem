### Added: a domain's page shows the ports of its resolved addresses

- `GET /api/v1/assets/{id}/resolved-ports` lists the open ports of the addresses a domain or subdomain resolves to (name `resolves_to` address `exposes` open port), with the address, service, product, version and last seen time. Each address and port is filtered by the caller's data scope; the others are only counted (`hidden_count`).
- `GET /api/v1/assets/{id}/view` answers the asset and the reads of its page's panels in one response (each part through its own endpoint's gates; a refused asset ends the view). The asset page loads through it, so the new section adds no request.
- The asset page of a domain or subdomain has a "Ports on resolved addresses" section.
