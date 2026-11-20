### Added: Paths on a web origin's page

- A web origin's page has a Paths tab: its endpoints as a tree of path segments. From 1024 px the tree sits beside
  the endpoints of the selected path; on a phone each level is a list with a breadcrumb back up. Each path shows how
  many endpoints and open findings lie under it, with a mark for a critical or high finding and one for paths under
  a scope exclusion, which stay listed.
- Filters hide static files (on by default), 4xx answers and gone endpoints, keep paths with findings, in or out of
  scope, or one method; the search covers paths. What the filters hide is counted, with Show all.
- The endpoint sheet lists the open findings at the endpoint's path (matched by path: findings record no method).
- A site never crawled says so, with Crawl this site for people who may scan it. The Web tab keeps the headers,
  parameters and changes; its endpoint list moved to Paths (search, the sheet and Export CSV included).
- On the Paths tab, and on the other tabs that hold a wide table (Findings, Relationships, Ports, Technologies, Web),
  the panel takes the page's full width from 1280 px and the properties list steps aside; below 1280 px it stays above
  the tab strip as before. The endpoints table hides its least important columns by its own width (parameters,
  content type, last seen, last status) so no column is cut at its edge.
- Docs: server/docs/architecture/web-surface.md

### Fixed: the Web tab of an origin stored as a service

- An origin stored as a service with the http sub-type (what ingest writes) did not get its Web tab, because the page
  only knew the legacy type names. It now gets Web and Paths.
- Docs: server/docs/architecture/web-surface.md
