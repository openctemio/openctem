### Added: shared list pieces for the Add filter key, row name links, folded filter keys, no-match words and risk columns

- `useAddFilterShortcut` is the one handler of the `f` key of "Add filter": it does nothing in a field, a menu or a dialog, with a modifier key, while a modal is open or in Query mode. The Findings list uses it.
- `RowNameLink` is the name of a row as a real link to its detail page: a plain click opens the detail overlay, a modified or middle click follows the link. The Findings title uses it.
- A clearable `FilterSelect` with `foldLabel` reads its key ("State") instead of "All" once the key folds away on a narrow toolbar, so two selects on one list never both read "All"; its accessible name is unchanged.
- `DataTable` `emptyState.noMatch` also takes `{ title, hint }`: the table keeps its icon, layout and Clear filters action and shows the words of the page.
- A `risk` column kind: start-aligned, 148 px wide, highest first.
- Docs: web/docs/ui/shared-kit.md, web/docs/ui-style-contract.md, web/docs/findings-list.md
