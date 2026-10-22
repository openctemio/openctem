# Findings list

How `/findings` behaves. The code is in `src/app/(dashboard)/findings/page.tsx`,
`src/features/findings/components/` (`finding-row-menu.tsx`, `finding-phone-card.tsx`) and the shared
`src/features/shared/components/data-table/`.

## Selection

- A selection belongs to the rows on screen. Changing the page, the page size, the sort, the search, a
  filter, the view or the grouping clears it, so a bulk action never reaches a row the user cannot see. The
  flat table does this itself for page, page size and sort (`DataTable`), and the page adds the filters,
  search and view to `resetSelectionKey`.
- Phone cards carry the same checkbox and the same action menu as a table row. The menu is one component
  (`FindingRowMenu`) used by both, so the two never offer different actions. Selecting a card is a
  separate control from opening it.
- Bulk assign goes through the shared client `post()`, so a step-up challenge is answered by the
  re-authentication dialog and an error body becomes the message.
- A click anywhere on a row opens the finding drawer, except on the row's own controls.
- `j` and `k` open the next and previous finding while the drawer is open, and are listed in Help,
  Keyboard shortcuts.
- The row menu items that need the full flow (assign, change status, mark as false positive) say they open
  it ("Open to assign…").

## Request budget

A cold load of `/findings` sends at most 5 API requests (`e2e/request-budget.json`).
