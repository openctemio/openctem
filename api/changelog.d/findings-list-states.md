### Changed: findings list empty and error states, and a translated list

- The Findings list tells three empty states apart: no findings yet (with Import results, Set up a scan and Integrations), no match (what the filters and search hide, with Clear filters and Search all statuses) and no access.
- A failed list shows as an inline alert in the table area, with Retry and a Copy request ID button; the page header, search and filters stay and no toast is added. API errors now carry the server's request id.
- Every string on the findings list, the shared table (pagination, density, columns, sort menu), facet panel, bulk action bar, filter button, saved-views menu and SLA badge is translated into English and Vietnamese. The column chooser lists column names instead of internal ids.
