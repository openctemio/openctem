### Changed: Assets opens sorted by risk, and filters open from Add filter only (redesign branch)

- The Assets inventory is sorted by risk, highest first (assets of one score by name), unless the address names
  another order: the Risk column shows the sort arrow, so the order on screen is explained by a column. The
  default order is not written into the address. Before, the list came newest first, an order no column showed.
- The docked filter panel is gone from the Assets inventory: from 768 px "Add filter" opens its picker; on a
  phone the Filters button joined to the search field opens every facet in a sheet, as before.
- The columns, filters and chips of a type list (for example "ASN organization", "Provider") show their Vietnamese
  names in Vietnamese: the label was always read in English.
- The severity breakdown in the asset drawer uses the 12 px caption size (its labels were 11 px).
- Docs: none (internal redesign branch)
