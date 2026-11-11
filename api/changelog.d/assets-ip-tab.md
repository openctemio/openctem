### Added: network, port and service filters and the IP addresses tab columns

- `GET /assets` filters `network=10.1.2.0/24` (the /24 of IPv4, the /64 of IPv6; an address means its network), `port=443`, `port:80,443`, `port>=8000`, and `service=https` (from `asset_ports`).
- Every address row of the list carries `ip`: its `network`, up to 3 names that resolve to it and up to 5 open ports, with totals; only names and ports in the caller's data scope are listed or counted.
- `GET /assets/networks` groups the addresses a list filter matches by network (at most 500, `capped` above), with the same params, registry and scope as the list.
- Migrations `20261108192453` (function `asset_ip_network`) and `20261108192454` (`idx_assets_ip_network`, built concurrently, partial on address assets; no row is rewritten).
