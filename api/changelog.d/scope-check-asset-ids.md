### Added: `POST /scope/check` checks inventory assets by id

- The dry run of the active-probe gate now also takes `asset_ids` (at most
  200 targets and assets together). Each asset is checked by its name, as a
  scan of it would be, and its result carries `asset_id` (RFC-054 §6.4).
- An asset outside the caller's data scope, another organization's, deleted
  or unknown answers `out_of_data_scope` with its id only, whichever it is:
  the check reveals no asset name and no existence.
- `targets` is no longer required when `asset_ids` is sent.
