### Fixed: Credential leaks list pages on the server and shows real data

- The list now pages, sorts and filters on the server (page, page size, sort, source and severity are in the URL), so leaks past the first 100 can be reached. Export writes every leak that matches the filters.
- The invented Classification column is gone; a Severity column shows the severity the API returns, and the drawer shows it unchanged.
- "Leak date" uses the breach date when the import gave one, and the first-seen date is labelled "Discovered". The "Recent" badge follows the breach date.
- The Source filter uses the API source types, and the Critical and High tiles filter the list. The "Pending" status option, which listed every active leak, is removed.
- A failed list or related-leaks request shows an error with Retry, and the Related tab shows an empty state.
- The page, the secret field and the credential type names are translated (English and Vietnamese).
