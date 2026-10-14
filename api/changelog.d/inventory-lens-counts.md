### Added: asset counts on the inventory lenses, with type chips

- `GET /api/v1/assets/stats` returns `by_type_sub_type` (keyed `type` or `type/sub_type`, data-scoped like every other count), so the web places each asset in its registry lens.
- The inventory's lens bar shows each lens's count, hides lenses with no asset, adds **Other** for assets outside every lens (unclassified), and with a lens picked lists its asset types with counts as multi-select chips (`?types=`). The type filter in the side panel is removed: the bar is the one place to filter by type; saved views and links with `?types=` keep working.
