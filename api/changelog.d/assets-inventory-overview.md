### Added: inventory overview by area

- `GET /api/v1/assets/overview` (`assets:read`) counts the caller's assets per lens, type and sub-type in one aggregate: the assets the default inventory lists, the unowned, high-risk (score 70 or more) and new-this-week ones among them, and the names awaiting attribution review. Counted within the caller's tenant and data scope.
- The category view of `/assets` is rebuilt on it: one card per registry lens with its types and what needs attention, each count opening the filtered inventory; an empty area says how to discover its assets. The counts now match the lists they open (names under review or marked not ours are no longer counted as inventory), and a new asset type shows up with no web change.
