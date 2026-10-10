### Added: the software an asset runs and its matched CVEs

- `GET /api/v1/assets/{id}/software` (asset read permission and data scope; an asset outside the caller's scope or organization answers 404) lists the products and versions scans saw on the asset, each with the CVEs its version falls in: confidence, likely/potential label, the affected range and whether the organization's policy makes it a finding (RFC-066).
