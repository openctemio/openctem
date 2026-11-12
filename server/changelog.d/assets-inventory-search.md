### Added: asset inventory search box, type tabs and saved views

- The asset inventory filter bar has the Query toggle of the findings list: the filter as one line of query text on the shared search box, written back as flat URL params when the chips can show it and kept whole as an Advanced chip when they cannot (an OR across fields, a group).
- Inside the External surface lens the type is a tab with a count: Domains, Subdomains, IP addresses, Services, Web endpoints, Certificates (`?lens=external_surface&tab=ip_address`). A tab is a locked type condition. Old `types=<one type>` links open the matching tab; other lenses keep the type facet.
- The IP addresses tab shows the address's Network /24 (a click filters to it), the names that resolve to it, and its open ports, and can group the addresses by network.
- Saved views work on the inventory (page `assets`, personal, shared with a group or the organization). The old quick Views became built-in starter views, with a few more for each tab.
- Totals show "10,000+" when the list stopped counting at 10,000.
- The web console now sends the list query contract's parameter names to `GET /api/v1/assets`; the deprecated names still work until 2026-12-20.
