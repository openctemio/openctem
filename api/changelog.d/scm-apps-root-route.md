### Fixed: the API starts again (empty route pattern in the GitHub App routes)

- `GET /api/v1/ci/scm-apps` was registered with an empty pattern inside its group, which chi refuses with a panic at start-up. It is now `/`. A test fails any empty route pattern in the route files.
