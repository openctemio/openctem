### Added: the `monitor.web_content` capability, so page monitoring can fetch

- The stage catalog lists `monitor.web_content@1` (tier T1, input a web URL, run by `httpx` only for a step or job that names it; a step that pins `httpx` alone is still the HTTP probe). The capability reports no asset of its own: the capture is the `web_content` property of the web asset the URL belongs to.
- It is an active capability: coverage sends it through the same dispatch gate as every active fetch (scope entry, exclusions, tier ceiling, the claim-time re-check), as the coverage policy and never as a member.
- Updates the CTIS dependency to v1.6.5, which defines the capability and carries the capture through the `httpx` mapping.
