### Changed: an empty list shows its empty state without column headers

- A list with no rows (nothing yet, nothing matches, or a load error) kept its column headers and, on lists with bulk actions, an unchecked "select all" box above nothing. The empty state or error now stands alone in the list's frame; the headers come back with the rows, and stay while a list loads (every list).
- Docs: web/docs/ui-style-contract.md (empty list without headers)
