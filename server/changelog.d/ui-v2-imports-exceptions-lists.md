### Changed: the Imports and Exceptions lists follow the shared list pattern (redesign branch)

- Imports (/findings/imports, formerly "Import and run receipts"): columns in the order Source, Status, Started,
  Received, New, Resolved, Not stored, then Still detected, Reopened and Suppressed, which step aside on a narrow
  table. A Source filter (upload, scan run, scan task, CI run, connector sync, sensor report, platform match) is
  read by the server; the origin, tool and period a dashboard figure opens the list with show as removable chips
  under the toolbar. "Import results" opens the import form from the toolbar for people allowed to import.
  Clicking a receipt opens it in a side sheet with what the run did and where the other findings went (no extra
  read). On a phone each receipt is one card: the tool with its status, the source and time, then received, new
  and resolved.
- Exceptions: the strip counts rules pending approval (with the age of the oldest), ending in 7 and in 30 days,
  approved and expired; each opens the list filtered. Type and State filters, the search, Refresh and
  "New exception" sit in one toolbar. Columns: Name, Type, State, Expires, Approved by, Requested by; people are
  shown by name instead of a shortened id. On a phone each rule is one card.
- Both lists show the shared states: a first-use empty state, "No ... match these filters" with Clear filters,
  a loading table and a retryable error.
- Permissions are unchanged: importing needs findings write, assets write and assets import; approving,
  editing and deleting a rule keep their own permissions, and the API checks every action again.
- Docs: none (the redesigned console is documented when it ships)
