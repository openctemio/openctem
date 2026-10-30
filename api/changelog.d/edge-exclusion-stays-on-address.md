### Behaviour change: an exclusion of a CDN edge address no longer excludes the names behind it

- An exclusion of an address inside a range a CDN, edge or hosting provider publishes for a shared front end now blocks only that address (bare, `host:port`, URL, and inside range targets) on every dispatch path. Names that resolve to it keep being scanned through the edge; their port scans are capped to the web ports. Before, one exclusion of a shared edge address stopped scanning every name the organization served through that provider.
- An exclusion of any other address (dedicated, a cloud static address, or one labeled an edge only by its network holder or CDN record) still excludes every name that resolves to it.
- A port scan of a name served through a shared front end is capped to the web ports even when a scope entry covers the edge address.
- `POST /scope/exclusions/bulk/preview` adds `resolving_names` and `resolving_sample` (names an address, range or CIDR exclusion also stops, within the caller's data scope) and, for a shared front end, `edge` and `names_unaffected`.
