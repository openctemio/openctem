### Added: create a scan from inventory assets by id

- `POST /api/v1/scans` accepts `asset_ids`: the server scans each asset by its inventory name, checked like any typed target (act scope, ownership, proof, tier). An asset the creator may not scan, another organization asset or an unknown id refuses the request without saying which. At most 1,000 targets and assets together.
