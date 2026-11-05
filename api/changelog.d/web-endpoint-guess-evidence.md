### Security: the platform decides how a web endpoint was found

- The source of a reported web endpoint now comes from the capability of the command the report is bound to, not from the report: a crawl reports `crawl`, `js`, `sitemap` or `robots` (anything else it claims is stored as `crawl`), and only a path discovery job (`enumerate.web_paths`) produces the new source `guess`.
- A guessed endpoint is stored only with response evidence (`extensions["io.openctem"].response`: body size and a 16-hex hash of the normalised body); without it the endpoint is refused and counted in `endpoints_no_evidence`.

### Added: response evidence on web endpoints

- Web endpoints return `resp_size` and `resp_hash` when path discovery confirmed them, and `GET /api/v1/web-endpoints` accepts `source=guess`.
- Migration `20261105051408_web_endpoint_response_evidence` adds two nullable columns to `web_endpoints` (no rewrite, no backfill).
