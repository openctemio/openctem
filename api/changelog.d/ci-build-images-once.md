### Changed: CI builds each image once per content key and shares it across workflows
- `build-images.yml` builds the API, web, console, admin CLI and all-in-one images once per content key (git tree hashes of their build inputs), pushes them to `ghcr.io/openctemio/ci-images` with a build provenance attestation, and Web E2E, All-in-one CI and API CI use them by digest. Fork pull requests keep building locally.
- A daily job deletes CI images older than 14 days.
