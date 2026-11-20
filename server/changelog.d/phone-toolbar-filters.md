### Fixed: list filters on a phone are never hidden in a sideways strip

- On a phone (390 px) a list's filter tokens (status, kind, period, on/off
  filters) sat in a strip that scrolled sideways with nothing to say so: the
  token at the edge was cut ("Last 7 d...") and the ones after it were out of
  view. The list now shows one Filters button with the number of filters in
  force; it opens the list's filter sheet, where every token is. The filters
  in force stay on the line under the search, wrapping, and clear in place.
- Refresh moved from the title row into the toolbar on Asset activity, Scans,
  Workflows, Scan approvals and Ready to close, so no line holds an icon alone
  on a phone.
- Active filter chips wrap onto more lines on a phone instead of scrolling
  sideways, so none is hidden.
- The layout check (e2e spec 75) now flags a control a sideways scroller cuts
  at its edge, a one-line strip that hides a control, and a phone title row
  holding one icon alone.
- Docs: web/docs/ui-style-contract.md (Lists and tables, phone toolbar)
