### Fixed: CI runners are judged against their own release line

- The token exchange compared the CI runner's version (openctemio/ci, `openctem-ci/v0.2.0`) with the sensor minimum (`SENSOR_MIN_VERSION`, v0.9.0). Every released CI runner was refused with `RUNNER_OUTDATED`, and every pipeline showed as degraded with "below the minimum".
- CI runners now have their own settings, `CI_RUNNER_LATEST_VERSION` (default v0.2.0) and `CI_RUNNER_MIN_VERSION` (default none). They come from the new `ci` entry in `versions.yaml`, which also sets the release the console's pipeline snippets pin.
