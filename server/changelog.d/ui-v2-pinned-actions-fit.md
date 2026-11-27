### Fixed: a frozen row actions column is only as wide as its actions

- A list that freezes its row actions column at the end (Findings > Approvals, the asset suggestions and possible duplicates queues) sized it to its declared width on every row, so on rows without an action an empty strip covered the column before it. The column is now as wide as the widest action on the page, never wider than declared, and has no box while no row has an action.
- Docs: web/docs/ui-style-contract.md (frozen columns)
