### Behaviour change: CI runners v0.3.0 and later only

- openctemio/ci v0.3.0 is the CI runner release the console's snippets pin, and the oldest one the platform accepts (`CI_RUNNER_LATEST_VERSION` and `CI_RUNNER_MIN_VERSION` default to v0.3.0). A pipeline on v0.2.0 or older is refused with `403 RUNNER_OUTDATED`. Those releases read scanner configuration and ignore files from the scanned tree, which could hide findings.
- The GitHub snippet no longer grants `security-events: write`: v0.3.0 needs it only with `upload-sarif: true`.
- `403 RUNNER_OUTDATED` now tells the job exactly what to change. It names the runner's version, the minimum, and the line to pin, in each form: GitHub `uses: openctemio/ci/.github/workflows/scan.yml@v0.3.0` or `openctemio/ci@v0.3.0`, the GitLab `include` URL, or the image tag for other CI systems. Before, it said "update the sensor image".
- The how-to guides pin v0.3.0.
