### Added: scanner addresses to allowlist at a WAF or edge protection

- Settings, Scanning, Proxies has a "Scanner addresses" card: the addresses your scans leave from, with copy buttons and ready allowlist snippets, so a target owner can allowlist the scanner instead of the scan being blocked or challenged. API: `GET /api/v1/proxy-pools/scanner-addresses` (`sensors:egress:read`).
- Only addresses the platform observed itself are listed: a proxy endpoint's exit address is kept from a proxy test only when the platform's test echo saw that address for the same test (a sensor's report alone never adds one), your sensors' addresses are the ones the platform saw them connect from, and shared sensors' published egress is listed when the organization may use them.
- The retest and run help for edge-blocked results now point to the card.
- Migration `proxy_exit_addresses`: two new tables and a unique constraint on `proxy_endpoints`.
