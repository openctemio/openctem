### Fixed: the query field keeps the toolbar's height, fills a phone's width with suggestions, and works with saved views

- A query text the server refuses says its problem (with the column and the suggested fixes) in a status row under the list toolbar instead of inside it, so the toolbar row keeps its height and nothing in it moves. The row is one line as tall as the filter chips row, shares that row's line when a context chip or a view's locked chips are there, and is announced as before. Findings, assets and scans.
- On a phone the suggestions of the query field span the screen between the page gutters instead of the narrow field, with about eight one-line rows; inside a dialog they keep the field's width.
- With a saved view open, Query mode keeps the view's locked chips on screen, a text that names no state or practice leaves the view's own in force, Enter on an unchanged text changes nothing, and query text applied on top of a view marks the view as modified so Save view and Reset show.
- Docs: web/docs/findings-list.md, web/docs/ui-style-contract.md
