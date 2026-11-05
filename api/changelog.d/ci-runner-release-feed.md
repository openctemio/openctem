### Changed: CI runner releases reach instances through the release feed

- The signed release feed now lists the CI runner (openctemio/ci) next to the sensor products and the SDK. The effective CI runner release is the built-in `ci.latest` raised by the verified feed, never lowered; the token exchange, pipeline health, CI alerts and the console's pipeline snippets resolve it per use, so a CI runner release applies without a platform release or restart. `CI_RUNNER_LATEST_VERSION`, when set, still wins.
- `GET /api/v1/ci/settings` answers the release the snippets pin as `runner_release` (read-only).
- `ci.min` is v0.4.0, the first CI runner that speaks CTIS 2.0: an older runner is refused at the token exchange. The built-in `ci.latest` is v0.4.0.
- The release train refreshes every component's built-in `latest` from the published releases when it cuts a release; the release preflight no longer blocks on a `latest` behind the published release, only on a `latest` or `min` that is not a published release.
