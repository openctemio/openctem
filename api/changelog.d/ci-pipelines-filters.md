### Fixed: CI pipelines tiles, search and GitHub App callback

- The Inactive tile and switch change the list while a status tile is on (turning Inactive on clears the status filter). The Fresh tile filters and the CI pipelines tile clears the filters.
- The pipeline search waits 300 ms after typing before it asks the server, and the table columns are no longer rebuilt on every refresh.
- After the GitHub App installation is checked, the callback page removes the single-use code and state from the address bar and history, and names the product from the instance brand.
- Dates in the CI trust cards use the console language, and the old-audience sentence no longer says "until" twice.
