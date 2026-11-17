### Changed: the console Admin activity list follows the shared list pattern (redesign branch)

- Console > Admin activity: a title row with the view name ("Changes" or "All events") and the count once, with
  "Export this page (CSV)" at its end as the list's own action (it was in the page header). The kind view and
  Result stay in the table's toolbar; action, administrator and the two dates move into "Add filter" and show as
  chips under the toolbar (one row at 1440 px); a phone opens every filter from the Filters button. Rows are on one line (the action in words,
  then its code) and the action stays in view while the table scrolls sideways. IP address steps aside on a narrow
  table.
- The shared activity table (also on the console overview and an organization's activity tab) gets column kinds and
  widths, a table name, and its states: a failed read shows in the table with Retry while the filters stay; an empty
  list says whether nothing happened yet or nothing matches, with Clear filters (the kind view is kept).
- No API change: the same reads, filters, 50 a page, export and detail sheet.
- Docs: none (layout of an existing console list; what it reads and who may read it are unchanged)
