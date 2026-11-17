### Changed: the Scans list follows the shared list pattern (redesign branch)

- Rows are one line: the scan name (a link to the scan page; a plain click still opens the detail sheet), what it
  runs, its intensity in a column of its own, the latest run with its time, the recent runs, the run count and the
  schedule with its switch. The description moved to the name's hover text and stays in the detail sheet. The name
  stays in view while the table scrolls sideways; Intensity and Recent runs step aside on a narrow table and stay
  under Display > Columns.
- Toolbar: search (Basic | Query), Add filter, then State and Origin as two selects of a fixed width. Scan type,
  Schedule, Tag and "Show one-off scans" are set from Add filter (key `f`) and show as removable chips in one row under
  the toolbar, with Clear filters. The docked filter panel is gone; on a phone the Filters button joined to the search
  field opens every filter in a sheet.
- The title row has Refresh. An empty list says whether there are no scans yet or no scan matches, with Clear filters.
  A refused read shows the no-access notice.
- Selection uses the table's own checkbox column and bulk bar: Activate and Pause, then Disable and Delete under More,
  with the same confirmations. A user who can neither change nor delete scans gets no checkboxes. On a phone, Select
  in the list's More turns the checkboxes on.
- No API change: the same reads, filters, sorts and bulk endpoints.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged)
