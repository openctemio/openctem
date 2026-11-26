### Fixed: dashboard editor previews match the dashboard, and charts fill a stretched card

- Dashboard editor (Customize): the grid no longer gives each row a 128 px floor, so a preview is as tall as the widget will be on the dashboard, and it spans the same rows (one for the key figures strip and for a full-width widget with no figure). The freshness line shows only when a widget's time differs from the page's, as on the dashboard.
- The editor's "Taller" / "Shorter" items are now "Span one more row" / "Span one row fewer": a widget is as tall as its content, and the rows only place it beside its neighbours.
- The editor's widget header: every button at the kit's size (one height in the row), and the cut widget name keeps its full text in a tooltip.
- Dashboards: a time-series chart in a row whose neighbour is taller grows with its card instead of leaving a blank band under its legend.
- Docs: web/docs/ui-style-contract.md (Dashboard widgets)
