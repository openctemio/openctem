### Changed: the asset Activity list follows the list pattern (redesign branch)

- The Activity list under Assets has a title row (the kind on screen, its one count for the period, Refresh),
  Kind and Period as the toolbar selects, a Display menu, one-line rows with the asset name as a link and its
  type after it, and the shared pager (25, 50 or 100 rows).
- "Internet-facing only" is a toolbar button at the height of the selects beside it, pressed while on, and keeps
  its place for every kind: for Newly exposed it is pressed and locked, with the reason, so choosing a kind moves
  nothing in the toolbar. On a phone it reads "Internet-facing" so its label stays inside the toolbar strip.
- A long asset name ends in an ellipsis inside its column; it no longer widens the table past its frame.
- A user without access sees the shared no-access state.
- Docs: none (internal redesign branch)
