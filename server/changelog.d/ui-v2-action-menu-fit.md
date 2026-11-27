### Changed: phone action menus choose a small menu or a bottom sheet by fit (redesign branch)

- On a phone, `ActionMenu` now stays a small menu under its button, with 44 px rows and the 16 px gutter, when it has
  at most six items, no submenu, labels within two lines and room beside the button; a longer menu, one with a
  submenu, or one that would not fit opens as the bottom sheet. It measures this each time it opens; pages do not
  choose. The Findings page-header More (two items) is now a small menu on a phone.
- The bottom sheet keeps at least 16 px (or the safe area) under its last row and sits on the bottom of the visible
  screen, above a browser toolbar.
- The reason of an unavailable action shows as text under its label on a phone, in the menu as in the sheet.
- Docs: web/docs/ui-style-contract.md ("Action menus: ActionMenu")
