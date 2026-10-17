### Fixed: the findings list opened for an asset no longer jumps or sends a bad request

- Opening the findings list from another page (an asset's "View findings", for example) sent one list request with the previous page's sort and without the asset filter, which the API refused with 400, and then the real request. The page now waits until its own address is in place before it asks for anything, so it sends one request with the right filter.
- The active context filters (asset, scan, CVE, rule and the other group drill-downs) now sit in their own row under the table toolbar, so the toolbar keeps one height and its controls (state tabs, saved views, grouping, export) no longer move when a filter is set.
- The overview cards above the list (Total, Open, Critical open, ...) now count the findings of that context (for example the one asset) instead of every finding, so they agree with the list and the state tab counts. Facet filters, search and the state tab still leave the cards unchanged.
- The cards and tab counts keep their numbers while new ones load instead of blanking.
