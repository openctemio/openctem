### Changed: sensor and SDK releases reach the platform without a platform release

- The signed release feed now lists the newest release of each first-party sensor product and of the sensor SDK, with the image digest (RFC-037 §12). The instance learns them at start-up, after each daily check or import, and on every replica within the hour: "update available", the SDK status and the install commands follow a sensor or SDK release with no OpenCTEM change, release or restart.
- A learned release only raises the version this platform release was built with (`latest` in `versions.yaml`), never lowers it; `min` and the SDK advisories still come from `versions.yaml`. The install commands pin `image:tag@sha256:...` when the feed gave a digest; a mirror set with `SENSOR_IMAGE` is pinned by tag.
- `GET /api/v1/sensors/stats` products gain `latest_source` (`feed`, `built_in`, `operator`); the Sensors page says when "latest" is only the built-in version. The admin version check view gains `components`, listed on System > Software updates.
- The feed is published every 6 hours from the public release lists of the sensor, connector and sdk-go repositories; those repositories no longer open a pull request here after a release.
- Fixed: the helm and signature-check snippets took the tag from an image reference with a digest wrongly.
- `api/deploy/docker-compose.sensor.yml` now follows `versions.yaml` (it named v0.9.7 for the API image).
- **Upgrade note:** nothing to do. Until a release feed key is pinned in a release, the built-in versions apply as before; an air-gapped instance imports the feed file in the console.

### Changed: a missing release feed is visible

- The version check logs a warning when its outcome changes (feed not published, signature invalid, unreachable, expired) and once at start-up when the build pins no feed key; a 404 is reported as `not_published`. Console > System shows the feed state and the last success time.
- The `Release Feed` workflow fails with an error naming the one-time setup when `RELEASE_FEED_SIGNING_KEY` is missing, instead of skipping with a warning. Setup: `docs/architecture/version-check.md#setup-maintainers`.
