### Changed: the Exposures list follows the shared list pattern (redesign branch)

- Rows are one line: the exposure (its type icon and title, kept in view while the table scrolls sideways), the
  summary sentence in a column of its own, the threat signals in a column of their own, severity (a "Changed" mark
  with the reason in its tooltip when an analyst changed it), state, source and first seen. Source, Signals and
  Summary step aside on a narrow table and stay under Display > Columns.
- The title row names the lifecycle view (Needs attention, Closed, All states) and states the count once; search text
  or a filter shows Modified and Reset. Refresh and Export are in the same row; on a narrow row and on a phone they
  fold into More, which starts with Select.
- Toolbar: search, Add filter (key `f`) for Severity and Category, then State as a select of a fixed width (on a phone it is in the Filters sheet). Filters
  show as removable chips in one row under the toolbar, with Clear filters. On a phone the Filters button joined to
  the search field opens every filter in a sheet.
- Selection uses the table's own checkbox column and bulk bar: Resolve and Accept risk, then False positive under
  More, with the same confirmations and the same approval gate (disabled with the reason without `findings:approve`).
- Rows per page are 25, 50 or 100 (a link with another size keeps it).
- An empty list says whether there is nothing yet or nothing matches (with Clear filters); a failed read with rows on
  screen keeps the rows and says how old they are; without the read permissions the list shows the no-access notice.
- No API change: the same reads, filters and state changes.
- Docs: none (layout of an existing list; filters, actions and permissions are unchanged)
