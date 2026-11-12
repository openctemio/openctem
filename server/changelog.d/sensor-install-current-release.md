### Changed: a fresh install runs the current sensor, and the release train refuses an old one

- `versions.yaml` names the current releases: sensor v0.29.1 (was v0.23.2), sdk-go v0.41.0 (was
  v0.34.0), CI runner v0.3.1 (was v0.3.0). They are what an instance installs without the release
  feed: the bundled Compose sensor's default image, the chart's sensor tag at release, and the
  install snippets of an instance that cannot reach the feed. Instances with the feed already
  pinned the newer releases.
- The release train's preflight lists each release line of `versions.yaml` against the published
  release and blocks the cut when one is behind (fix: set it, run `sync-versions.sh`).
- **Upgrade note:** the bundled sensor (`api/deploy/docker-compose.sensor.yml`) moves to v0.29.1
  on the next `docker compose up -d` unless `SENSOR_VERSION` is set in `.env`. Its identity and
  outbox stay on the `sensor-data` volume; it does not pair again.
- Release Tooling checks that the seccomp profile the API serves and the bundled sensor runs is
  the pinned sensor release's file, and runs that release's install-guide test (when it has one)
  against the install snippet templates, so a setting or flag the sensor renamed fails CI.
