### Fixed: a scan of picked assets alone can be created

- `POST /scans` with `asset_ids` and no `targets` or asset groups was refused with 400 by the handler before the server could name the assets, so New Scan could not save a scan of assets picked in the inventory picker without also typing a target. It is accepted now; a request with no targets, assets or groups is still refused.
