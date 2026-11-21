### Added: a finding keeps its web location and its endpoint

- Ingest now stores the CTIS `web` location of a finding: its HTTP method, the parameter's location and name (never a value), the response status, and a link to the stored web endpoint. The link is set when the report's `endpoint_ref` resolves, or when the finding's method and URL template match an endpoint of the same origin and organization; an endpoint of another organization is never linked.
- The path tree counts a linked finding at its own endpoint and method. A finding with no link keeps the template mapping, which shows at every method of the template.
- A new table `finding_web_locations` (additive migration); findings stored before it keep the template mapping until their next sighting.
- Docs: server/docs/architecture/web-surface.md
