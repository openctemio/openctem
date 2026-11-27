### Changed: the sensors list follows the shared list pattern (redesign branch)

- Rows are one line: the sensor's name with its marks, the host and address in a Host column of their own, the
  state with the reason beside it (the heartbeat age when there is nothing to say), the version with its tags, the
  jobs and the tools. The name stays in view while the table scrolls sideways; Host and Tools step aside on a
  narrow table and stay under Display > Columns.
- Title row: the list's name, the count once, the live mark, then Refresh content, Refresh and Export. On a phone
  Refresh, Export and the way to the approve page are in one More, after Select.
- Toolbar: search, Add filter (key `f`) with every facet, Group and Display. A facet in use shows as a removable
  chip in one row under the toolbar, with Clear filters. The docked filter panel is gone; on a phone the Filters
  button joined to the search field opens the same facets in a sheet.
- Selection uses the table's own checkbox column and bulk bar: Disable, then Delete under More, with the same
  confirmations (the count and the names, the typed confirmation for Delete). A user who can neither change nor
  delete sensors gets no checkboxes. On a phone, Select in the list's More turns the checkboxes on.
- Every action keeps its dialog as it was: Edit, Rotate key, Enable, Disable (confirm), Revoke (typed name), Delete
  (typed name). The row menu has the same items in the same order, on the table row and on the phone card.
- States: skeleton rows under a toolbar that stays, the load error with Retry in the rows' place, the no-access
  notice on a refused read, no match with Clear filters. The first-run block (how to add a sensor) is unchanged.
- The list still refreshes itself every 15 s; rows under the pointer keep their places through a refresh.
- Phone: the list comes first; the pipelines line, shared scanning, the cleanup hint and the fleet health follow it.
  Add sensor is a named icon button in the title row; cards have the row menu.
- No API change: the same reads and the same writes, each with its permission check and audit on the server.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged)
