### Fixed: a release checkout installs its own version

- Before, `versions.yaml` `platform.release` was bumped only after tagging, so
  the `vX.Y.Z` tag's `api/deploy/.env.example` and `docker-compose.yml`
  defaulted to the previous release: `setup.sh` on a v0.9.0 checkout installed
  v0.8.0 images. The release branch now carries its own version, synced into
  every default, and the tag is refused otherwise.
