### Added: `refingerprint -clear-legacy-secret-fingerprints`

- Secret findings created before the keyed fingerprint carry a value computed from the tenant id alone, which cannot be verified and is never rewritten. The new tool mode clears them in batches without long locks (dry run by default, `-apply` to commit, `-before` and `-tenant` to narrow it), so the next sighting writes the keyed value. A secret seen again may open one new finding next to the cleared one; see `docs/deployment/encryption-key-rotation.md`.
