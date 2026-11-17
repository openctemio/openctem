### Changed: the console Organizations and Sessions lists follow the shared list pattern (redesign branch)

- Console > Organizations: a title row with the count once; search, Status and Owner in the table's own toolbar, with
  Display at its end; rows on one line (the name is a link to the organization, its slug beside it) and the name stays
  in view while the table scrolls sideways. Limits, Single sign-on and Created step aside on a narrow table and stay
  under Display > Columns. The list shows 25 organizations a page (was 20). An empty list says whether there are no
  organizations yet or none match, with Clear filters; a failed read shows in the table with Retry.
- Console > Sessions: a title row with the count once; rows on one line. "End session" moved from a button in the row
  to the row's menu; it opens the same confirmation, which still asks for a reason and a fresh code. The current
  session's row has no menu, as before.
- Nothing else changes: the same reads and permissions, the same filters, the same Create organization dialog. No API
  change.
- Docs: none (layout of two existing console lists; what they read, who may read them and how a session is ended are
  unchanged)
