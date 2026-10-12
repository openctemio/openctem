### Added: asset list filters by asset group and owner

- `GET /api/v1/assets` filters by `asset_group_ids` (members of these groups) and `owner_ids` (owned by these users or groups), at most 20 each, within the reader data scope.
