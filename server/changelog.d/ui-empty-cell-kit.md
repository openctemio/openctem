### Changed: one empty table cell for every list (redesign branch)

- The muted dash of a table cell with nothing to show is a shared component, so the tenant app and the platform
  console draw empty cells the same way instead of writing their own dash.
- The shared cells that wrote their own dash use it now: a missing time, a missing EPSS score, an action with
  nobody recorded and a queue item that waits for no decision. Each empty cell says why on hover.
- Technologies: the Exploit column shows the muted dash with "No known exploit" on hover.
- No API change.
- Docs: none (the look of an empty cell is unchanged apart from the muted colour and the hover text).
