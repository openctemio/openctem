### Changed: the console Users list follows the shared list pattern (redesign branch)

- Console > Users: a title row with the view name ("All accounts", or the chosen state) and the count once; search and
  the State select in the table's own toolbar, with Display at its end; rows on one line. The account is a link to its
  page and stays in view while the table scrolls sideways; "Signs in with" and "Created" step aside on a narrow table
  and stay under Display > Columns.
- An empty list says whether there are no accounts yet or none match, with Clear filters; a failed read shows in the
  table with Retry and the toolbar stays. The three-character search hint sits in the row under the toolbar.
- Nothing else changes: the same read (`platform.users.read`, audited by the server), the same search, states,
  columns and page size, and no action on the list. No API change.
- Docs: none (layout of an existing console list; what it reads and who may read it are unchanged)
