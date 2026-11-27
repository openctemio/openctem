### Fixed: asset names are readable in narrow lists

- On a 1024 px screen the asset lists (inventory, attention queues) cut each name to a few letters ("Paymen...") because the type label ("Domain", "HTTP Service") sat beside it in the same narrow column. The type now shows beside the name only when the column has room for both; otherwise the name gets the width and the type is in the name's tooltip (the type icon stays).

Docs: web/docs/ui-style-contract.md (Row density, name column)
