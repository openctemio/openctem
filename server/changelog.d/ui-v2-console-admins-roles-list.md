### Changed: the console Administrators and Roles lists follow the shared list pattern (redesign branch)

- Console > Administrators: a title row with the count once; the table search, then Display at the toolbar's end;
  rows on one line (name, then the address) and the administrator stays in view while the table scrolls sideways.
  "Last tested" and "Sign-in" step aside on a narrow table and stay under Display > Columns. Every row menu is named
  after its administrator; each item opens the same confirmation as before, and your own row has no menu.
- Console > Roles: the roles and their holders are two titled lists, each with its count. Roles show their description
  on the same line. "Give a role" moved from a button in the row to the row's menu; it opens the same dialog (role and
  reason). Taking a role is still the cross on its badge, never on your own row.
- Empty lists say so, a failed read shows in the table with Retry. No API change; the same reads, permissions,
  confirmations, reasons and step-up.
- Docs: none (layout of two existing console lists; what they read, who may act and how are unchanged)
