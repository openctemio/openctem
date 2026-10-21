### Fixed: restricted members see the attack paths to their own assets

- Attack-path scores and exposure chains were cut to the tenant-wide top 50 / 100 before the viewer's data scope was applied, so a member whose assets ranked lower saw an empty list. The scope is now applied first, then the cap.
- An exposure chain to an asset in the member's scope is now shown even when it crosses assets outside their scope. Those steps are returned as hidden steps (`"hidden": true`, no id, name, type or exposure) in the `/attack-surface/exposure-chains` response and the MCP `exposure_chains` tool. Before, the whole chain was hidden.
