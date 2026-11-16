### Changed: one overflow menu per list page, never one of a single item (redesign branch)

- The shared action menu never opens a menu of one item: when only one action is left (after permission and width
  folding) and it has an icon, the "More" button becomes that action in the same place and size; outside production a
  console error names any one-item menu so a page does not ship one.
- Findings: wide, the view's title row ends with Refresh, Export and Task from filters (no More); Copy link moves to
  the page header's More under "This view", after Import results and Approvals. Narrow (and on a phone), Export and
  Task fold into the title row's More with Copy link, and the header's More does not repeat it; a header with a single
  item at that width merges into the title row's More.
- Docs: web/docs/findings-list.md (More menu).
