### Added: MCP search_assets and get_asset

- `search_assets` searches the assets the connection can see like the console's inventory: free text, an IP or CIDR, a CVE (assets with an open finding of it), type, exposure, criticality, internet facing, monitoring state, scope status, owner, technology and whether it has findings. Riskiest first, paged, each row with a link to the asset page.
- `get_asset` returns an asset as its page shows it, by id or exact name: overview, open findings by severity with the top ones by priority, coverage per capability, open ports and services, lineage and recent changes. `sections` asks for fewer. Each section is the asset page endpoint's own response, under the same data scope.
