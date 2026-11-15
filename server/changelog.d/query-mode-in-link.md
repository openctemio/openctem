### Changed: the search mode is part of a list's link

- The findings, assets and scans lists keep the search field's mode in the URL (`mode=query`), so a shared link or
  a reload opens in Query mode with the query text in the field; without the parameter the list opens in Basic mode
  as before. A Query-mode link whose text is refused opens in Query mode with the problem shown.
- Saved views of the findings and assets lists store the mode in `page_params` (`mode`: `basic` or `query`), sent
  beside the filter on `POST`/`PUT /api/v1/views`, and open in it. Any other value is refused (400).
- Docs: server/docs/architecture/query-language.md ("Web")
