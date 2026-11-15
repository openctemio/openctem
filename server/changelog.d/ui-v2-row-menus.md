### Changed: row menus and the bulk bar's More use the shared action menu (redesign branch)

- Every table row menu, the finding row and card menu and the bulk bar's More now use `ActionMenu`: on a phone a
  short menu stays a small menu under its button and a long one (the finding menu) opens as a bottom sheet titled
  with the row's name; from 768 px up they are menus inside the 16 px gutter.
- Row menu items gated by a permission or an API route are hidden from users who may not use them, as before; an
  unavailable item always says why (a general reason where the page gives none), as visible text on a phone.
- Row menu buttons are named after their row ("Actions for {name}") instead of "Open row actions".
- A click in a row menu or its sheet no longer reaches the clickable row or card around it.
- The menu's code loads right after the page shows instead of with it; a tap made before it is in still opens the
  menu. Pages' first-load JavaScript is unchanged (median 458 KB).
- Docs: web/docs/ui-style-contract.md ("Action menus: ActionMenu")
