### Fixed: dashboard widgets are as tall as their content

- Dashboards: the grid no longer gives each stored row a 128 px floor, so a widget saved taller than its figure (the CTEM loop saved two rows tall stood about 120 px of empty card under its tiles) is as tall as its content at every width. A widget's stored height still places it beside its neighbours, and widgets of one row share its height.
- The CTEM loop: the tiles stretch to the card, and "Act here" sits on the stage's note line instead of a row of its own, so every tile keeps one height and the status chips one baseline.
- Docs: web/docs/ui-style-contract.md (Dashboard widgets: a widget is as tall as its content)
