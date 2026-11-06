### Removed: the unused "asset tags" permission scope type

- The permission scope type `asset_tags` (and its siblings `all`, `owned_assets`, `asset_type`, `severity`, with the `ScopeValue` document) was declared in the access-control domain but nothing stored or enforced it: a role could never carry such a scope, and nothing read one. The unused declarations are removed so they cannot be mistaken for a working restriction.
- Nothing changes at runtime and no data is touched. Tag-based access is, and stays, the team scope rule `tag_match` (data scope), which is enforced.
