### Fixed: Asset groups list after its move to the list pattern (redesign branch)

- A long group name ends in an ellipsis inside its cell; it was drawn over the next column.
- The list keeps the order the API returns: the table sorts in the browser and took no initial order from the page,
  so the announced "sorted by name" never applied.
- On a phone the metric strip is not drawn (the count is in the title row, Criticality in the Filters sheet), so
  the first group card starts higher, and the search placeholder fits its field.
- Docs: none (internal redesign branch)
