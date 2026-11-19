### Changed: the Credential leaks list follows the shared list pattern (redesign branch)

- Rows are one line: the identifier with its credential type (kept in view while the table scrolls sideways),
  source, username, leak date with a "Recent" mark, discovery date, status and severity. Username, Discovered and
  Source step aside on a narrow table and stay under Display > Columns.
- A title row names the view ("All credential leaks"), states the count once (leaks, or identities when grouped)
  and shows Modified and Reset when a filter, the search, the order or the grouping is changed. Refresh and Export
  are in the same row; on a narrow row and on a phone Export and Reset fold into More. Export moved there from the
  page title and keeps its confirmation.
- Status, severity and source are in Add filter (key `f`), each with several values, and on a phone in the
  Filters sheet joined to the search field together with the grouping. Every filter shows as a removable chip.
  Grouped by identity, only the search and the status apply (the identities endpoint takes no other filter).
- Phones show the list first (the tiles follow it) with one card per leak in fixed slots; the secret is never on a
  row or a card. Empty, no match, loading, error and no access each have their own state. The identity grouping's
  texts are translated.
- No API change: the same reads, sorts, tiles, sheet, export and permissions; the filters send the lists the API
  already takes.
- Docs: server/docs/architecture/credential-leaks.md (the Credentials list)
