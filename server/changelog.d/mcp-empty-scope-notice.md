### Fixed: MCP tools explain an empty data scope

- An MCP connection reads only the assets the user's groups and scope rules grant, not the full-data access an owner or administrator has in the web console. A user in no group therefore got empty assets, findings, finding statistics and active CVEs that looked like an empty organization. Every such empty result now carries a `scope_notice` saying the user's data scope covers 0 assets and to ask an owner for access. The MCP authorization docs now state the rule (they said tokens kept full data access).
