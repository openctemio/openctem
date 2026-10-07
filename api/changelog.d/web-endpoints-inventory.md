### Behaviour change: crawled URLs are web endpoints under their origin, not assets

- A crawl (CTIS 1.6 `endpoints[]`, or a legacy `discovered_url` asset) now writes the web surface
  sub-inventory: one row per origin, method and path template in `web_endpoints`, and the parameter
  names in `web_endpoint_params` (migration 001222). No `discovered_url` asset, attribution record or
  graph node is created per URL any more; the origin's `http_service` asset is created when missing.
- Query values, user info and fragments are never stored, and token-like path segments are templated
  and masked before storage.
- A command-bound report writes endpoints only under origins its targets cover; endpoints land only on
  an origin asset the report may change. Only a tool whose stage reports endpoints (web crawl, web
  application scan) and whose declared contract names `endpoint` may write them.
- Caps: 5,000 active endpoints and 500 scripts per origin, 100 parameters per endpoint.
- A crawl step chained into a template scan now hands it the origin, not every crawled URL.
- Design: RFC-056.
