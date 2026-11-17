### Changed: the console Content catalog list follows the shared list pattern (redesign branch)

- Console > Content catalog: "Publish a package" and "Import a bundle" are the page's own actions in its header (the
  same conditions: shown to a super admin, Import disabled without trust roots, and disabled until the trust state
  is read); the Trust card keeps the read-only trust state.
- Nothing moves on first load: the header actions are drawn from the first frame and the package list comes once
  the trust state above it is read, so its title row and toolbar are drawn where they stay (they dropped 148 px).
- The package list has a title row with the type view and the count once; the search and the type select are the
  table's own toolbar; rows are on one line (the title, then the package id) and the package stays in view while the
  table scrolls sideways; Source steps aside on a narrow table. A failed read shows in the table with Retry while the
  toolbar stays; an empty list says whether the catalog is empty or nothing matches, with Clear filters.
- No API change: the same reads, 25 a page, the versions sheet and its Revoke dialog.
- Docs: none (layout of an existing console list; what it reads and who may change it are unchanged)
