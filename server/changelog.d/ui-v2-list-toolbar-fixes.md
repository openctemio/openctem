### Fixed: list toolbar, phone filter strip and the Findings practice first run (redesign branch)

- One filter entry per width on Findings and Assets: from 768 px "Add filter" sits right after the search field
  (before Practice and State, so it never moves when they change) and the field stands alone with four round
  corners; on a phone the Filters button joined to the start of the field is the one entry (no second Add filter).
  The search field joins a filter button only while that button is drawn.
- Phone: the filter chip strip always starts at its first chip, never cut at the start; only its end fades, and a
  leading chip wider than the strip shortens its text instead of being cut.
- Findings on a phone: "Select" is the first item of the list's More (beside Refresh), followed by a divider; the
  toolbar's own one-item menu is gone.
- The Findings list More uses the shared action menu (a menu or a bottom sheet by fit) and gains "Copy link",
  which copies the list as shown (filters, sort, view) for the current organization.
- "Clear filters" is drawn by the shared chip row, in the same place on every list with chips; emerging threats,
  exposures and technologies gain it.
- Findings, a practice with nothing yet (for example Compliance with no benchmark checks): the table says so with
  the practice's next step ("Import results", for those who may import), instead of a block above the list and a
  "No findings match" below it. The benchmarks block shows only when there are benchmarks and no longer pushes
  the list down when it loads. Choosing a practice keeps the view's name (it no longer turns into "Custom view").
- My work: the "SLA due in 72 hours" toggle is a standard button at the row's control height.
- Docs: none (internal redesign branch)
