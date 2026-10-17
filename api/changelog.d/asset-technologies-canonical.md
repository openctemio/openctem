### Behaviour change: technologies are no longer an asset property

- The technologies detected on an asset live only in the asset technologies list (RFC-112). Set
  reconciliation writes them there (one per name: when two tools report different versions, the
  better version is shown) and `assets.properties.technologies` is no longer written or read.
- Asset responses (`GET /api/v1/assets`, `/assets/{id}`, `/assets/{id}/full`) embed `technologies`
  (name, version, category): at most 20 per asset on a list, all of them on one asset.
- `properties.technologies` and its synonym `technology` are dropped on every asset write; the
  `asset-technology-backfill` job removes the stored key from existing assets in batches. Tags are
  never removed (a tag carries no origin); new reports no longer add technologies as tags.
- Upgrade note: API clients that read `properties.technologies` read `technologies` instead.
