### Added: first-party content packages and the bundle generator

- `cmd/content-bundle` creates the catalog keys (`keygen`, `keyset`) and builds the signed first-party bundle
  (`build`) from the sast-rules release (its Sigstore signature reused as the publisher signature), the sensor
  products of `versions.yaml` (image digests resolved at build time) and the program and vulnerability feed key
  sets (RFC-099 §6).
- Describing the sources as packages changes nothing in how rules, images and feeds are delivered.
