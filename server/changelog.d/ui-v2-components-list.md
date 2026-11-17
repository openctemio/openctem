### Changed: the Components list follows the shared list pattern (redesign branch)

- Rows are one line: the package name (a link to its page, kept in view while the table scrolls sideways) with its
  ecosystem and package URL, versions in use, assets, open findings by severity with the KEV count, risk, fix,
  licenses. Fix and License step aside on a narrow table and stay under Display > Columns; Last seen is under it too.
- A title row names the view ("All packages"), states the count once and shows Modified and Reset when a filter,
  the search or the order is changed. Refresh, Export SBOM and More (Import VEX) are in the same row; on a narrow
  row and on a phone Export SBOM and Reset fold into More. Import SBOM is the page's primary action in the page
  title (an icon on a phone).
- The docked filter panel is gone: the same facets open from Add filter (key `f`), and on a phone from the Filters
  button joined to the search field. Every filter shows as a removable chip in one row under the toolbar, with
  Clear filters.
- Phones show the list first (the tiles follow it) with one card per package in fixed slots. Empty, no match,
  loading, error and no access each have their own state.
- No API change: the same reads, filters, sorts, presets, dialogs and permissions.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged;
  `server/docs/architecture/software-components.md` describes the new layout)
