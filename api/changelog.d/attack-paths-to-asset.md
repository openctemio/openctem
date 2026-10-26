### Added: attack paths to one asset

- `GET /api/v1/attack-surface/attack-paths/{id}` returns the routes from internet-facing entry points to an asset, the finding that enables each step with its weight and basis (EPSS, KEV, severity or assumed), the likelihood of each route as the product of its step weights, and the choke points ranked by the number of routes they cut.
- Gated by `assets:read` and the attack surface module. An asset outside the caller's data scope or tenant answers 404; steps outside the scope are hidden, their findings are not read and the likelihood of a route through them is withheld.
