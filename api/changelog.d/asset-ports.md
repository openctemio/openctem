### Added: open ports of assets

- New derived table `asset_ports` (migration `20261108191259`): the open ports each asset answers on (the open_port service, the address that exposes it, the names that resolve to that address), kept current by the `asset-ports` worker from a trigger-filled queue. It backs the asset list's port and service filters and its Open ports column. Every live service asset is queued once on upgrade; the worker fills the table in the background. Design: `docs/architecture/asset-ports.md`.
