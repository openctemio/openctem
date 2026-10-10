### Added: passive discovery and continuous-discovery building blocks

- Two starter workflows (migration `passive_discovery_workflows`): **Passive
  discovery** (subdomains from passive sources, then DNS through recursive
  resolvers; nothing sent to the target hosts) and **Probe new assets** (port
  scan and HTTP probe, no discovery step) (RFC-071).
- `target_options.new_since_last_run`: a `*.example.com` selector takes only
  the assets that came into scope since the scan's previous successful run
  (attribution confirmed since then, or first seen since then without a
  record); never needs_review, candidate or rejected names. The first run
  takes every such asset.
