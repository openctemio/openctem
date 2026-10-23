### Fixed: Component pages show errors and empty states, and keep their filters honest

- Choosing a version or toggling "Include closed findings" returns the table to page 1.
- The Versions, Where used, Vulnerabilities and dependency path tables and the graph dialog show an error with Retry when a request fails, and an empty state when there is nothing to list.
- A vulnerability row links to the findings list by vulnerability id; a row with nothing to link shows plain text.
- The list tiles count the whole inventory, and a tile opens exactly what it counts. Tiles with no data (Outdated, Latest version) are hidden.
- The Where used version is kept in the URL. "Include closed findings" and the page size use the shared Checkbox and Select.
