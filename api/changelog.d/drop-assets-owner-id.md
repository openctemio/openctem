### Removed: the assets.owner_id column (migration 001056)

- `assets.owner_id` and its two indexes are dropped. Asset owners live in
  `asset_owners` since migration 000340; no code reads the old column.
- **Upgrade note:** upgrade from a release before the owner model change in
  one step (migrate, then restart every API pod). Old pods still running during
  a rolling update would fail asset queries until they are replaced.
