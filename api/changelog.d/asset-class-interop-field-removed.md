### Behaviour change: asset classes no longer carry an external mapping hint

- `GET /api/v1/asset-types` no longer returns `jupiterone` on each class. Nothing in OpenCTEM read it; the class `id`, `label`, `lens` and `types` are unchanged. The `jupiterone` key is no longer accepted in `configs/asset-types.yaml`.
- The Vulnerability Management Essentials module preset describes its target persona without naming other products.
