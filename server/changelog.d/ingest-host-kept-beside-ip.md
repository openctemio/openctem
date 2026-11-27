### Fixed: a scanned host linked to a known address keeps its own asset and name

- A host a report names (for example `srv-web-00.corp.example.net`) with a `has_address` relationship to an
  address the organization already records as an IP address asset was merged into that address asset: the
  host's name was lost and the scanner's findings landed on the address. IP matching now matches a host only
  to a host and an address only to an address, so the host is its own asset that contains the address, and its
  findings stay on it. Hosts already merged this way are not split; the next scan of the host creates it.
- Docs: server/docs/architecture/asset-identity-resolution.md
