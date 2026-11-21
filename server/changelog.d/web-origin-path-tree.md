### Added: the path tree of a web origin

- `GET /api/v1/assets/{id}/web-paths` returns one level of a web origin's path tree: its child paths with the
  endpoints, out-of-scope endpoints and open findings under each (and the worst severity), and one page of the
  endpoints under the requested path. Filters hide static files, 4xx answers and endpoints not seen for 30 days,
  keep endpoints with findings, in or out of scope, or of some methods, and search the path. Findings are matched
  to endpoints by the link they carry or, without one, by path template whatever the method; a finding at a path no crawl recorded keeps its own node.
- Needs `assets:read`; an asset of another organization or outside the caller's data scope answers 404.
- Docs: server/docs/architecture/web-surface.md
