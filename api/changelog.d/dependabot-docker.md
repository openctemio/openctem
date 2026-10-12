### Added: Dependabot keeps the release images' base images current

- A weekly grouped Dependabot update covers the `FROM` images of every
  release image (`api/Dockerfile*`, `web/Dockerfile`,
  `deploy/allinone/Dockerfile`, `api/deploy/gateway/Dockerfile`): Go, Alpine,
  node, distroless and Postgres patch and minor releases. Majors stay manual.
