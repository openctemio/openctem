### Changed: the Assets inventory follows the list pattern of Findings (redesign branch)

- Rows are one line at the density heights (40, or 52 comfortable): the type follows the name on the same line,
  and a certificate's asset name follows its subject name. Columns have fixed widths by kind, so headers keep
  their whole word in English and Vietnamese; the name stays in view while the table scrolls sideways and the
  row menu is the last column.
- Selecting assets: the shared checkbox column (Shift-click and `x` ranges) and the shared bulk bar with two
  direct actions (Assign owner, Set criticality), More and Clear. Every other bulk action is under More, in the
  order the bar had them: Add to scope, Mark out of scope, Archive, Add tag, Remove tags, Add to unit, Add to
  service, a repository's own actions, then Delete. "Remove tags" is dimmed with the reason when the selection
  has no tag. Someone who may change nothing gets no checkbox column (the bar's read-only note is gone).
- The row menu is the shared action menu (a bottom sheet on a phone), the same on the table row and the phone
  card: Open details page, the asset's own actions, Edit, then Delete. "Sync from source" is dimmed with the
  reason on a repository added by hand.
- Phone: "Add asset" is a square in the title row beside the view switch (no row of its own); Refresh and Export
  are in the list's More with Select; the search field has a short placeholder; a list that shows every asset
  has no footer. Cards have fixed slots: the name, the type and its group or description as separate items,
  criticality in plain words ("High criticality"), and the risk slot on every card (a dash while there is no
  score); they have the row menu, and a checkbox once "Select" is chosen.
- The view name is the open saved view's name; "Modified" and Reset show beside it while the filter differs
  from the view.
- The list's More (after Refresh and Export) holds Select (phone), "Save filter as group", "Add all matching
  to group" and "Copy link". The two group actions no longer appear in and disappear from the toolbar with the
  filter: they are always listed, dimmed with the reason while there is no filter a group rule can hold.
- Rows per page are 25, 50 and 100; the pager says "assets". Views comes before Group in the toolbar.
- Without `assets:read` the inventory and the Needs attention queues show the shared no-access notice.
- The type-specific empty hints are translated.
- Docs: none (internal redesign branch)
