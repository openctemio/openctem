### Changed: Assets shows waiting scoping decisions as a count on the Needs attention tab (redesign branch)

- The Inventory tab no longer draws the "Decide monitoring" card between the tabs and the list: the list starts
  right under the tabs. The Needs attention tab shows how many assets wait for a monitoring decision (the kit's tab
  count, hidden at zero; screen readers hear "Needs attention 462 assets waiting", the visible text first). The landing still lists Decide
  monitoring with its explanation and count.
- No new request: the count is the same one-row request the landing's row sends; Groups and Activity show it only
  when that answer is already loaded. Inventory sends one request fewer than before.
- Docs: server/docs/architecture/exposure-taxonomy.md ("Scoping decisions")
