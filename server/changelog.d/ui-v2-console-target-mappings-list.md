### Changed: the console Target mappings list follows the shared list pattern (redesign branch)

- Console > Target mappings: a title row with the view ("All custom mappings", "Active mappings" or "Inactive
  mappings", set by the metric strip) and the count once; Target type and Asset type are the table's own filter
  selects (Clear filters is in each select and in the empty state). Rows are on one line (the target type, then what
  it means); the target type stays in view while the table scrolls sideways; Description and Updated step aside on a
  narrow table.
- A failed read shows in the table with Retry while the filters stay; "No custom mappings" (with New mapping) is the
  empty list's own state, "No mapping matches these filters" the filtered one. The row menu is named after its pair.
- No API change: the same reads, page sizes (20, 50, 100; 50 by default), and the same New mapping, Edit,
  Activate / Deactivate and Delete dialogs with their reason.
- Docs: none (layout of an existing console list; what it reads and who may change it are unchanged)
