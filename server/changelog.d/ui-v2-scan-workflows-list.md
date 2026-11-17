### Changed: the scan workflows list follows the shared list pattern (redesign branch)

- Title row: the view's name (all workflows, my workflows, system templates), the count once and Refresh.
- Toolbar: search by name, Add filter (key `f`), then Owner as a select of a fixed width. "Show retired" is set from
  Add filter and shows as a removable chip under the toolbar. On a phone the Filters button joined to the search
  field opens both filters in a sheet.
- Rows are one line: the name with its System and readiness marks, the status, the steps, the version, the Enabled
  switch and the row menu. The description moved to the name's hover text and stays in the detail sheet. The name
  stays in view while the table scrolls sideways.
- The list opens by name, A to Z, and the sorted column says so. Search text, sort, page and page size are in the
  address, so a view can be shared; the list is still read whole and narrowed on the page.
- States: skeleton rows under a toolbar that stays, "No workflows yet" with Create workflow, no match with Clear
  filters, the load error with Retry, the no-access notice on a refused read.
- Each Enabled switch names its workflow. On a phone, New workflow is a named icon button in the title row.
- No API change: the same read, the same row actions, dialogs and permission checks.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged)
