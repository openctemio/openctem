### Changed: the API contract files are generated, no longer committed

- `api/api/openapi/swagger.yaml`, `api/api/openapi/routes.txt`,
  `web/src/config/api-route-permissions.json` and
  `web/src/lib/api/generated/api.types.ts` are generated from the Go source by
  `make generate` (or `make generate-docker`, which needs only Docker) and are
  ignored by git, so pull requests no longer conflict on them and the merge
  queue can batch API changes.
- CI generates them on every run. API CI checks the spec against the handlers
  and the router as before; Web CI type-checks the web against the contract a
  change produces, runs the web checks for any API change that alters the
  contract, and reports the contract difference against the base (breaking
  changes, route gate changes, routes added or removed) on the pull request.
- Image builds (`docker-publish.yml`, all-in-one, e2e) generate before building
  the web image. `docker build web` from a plain checkout needs `make generate`
  first (`make allinone` does it).
- **Upgrade note:** a checkout that runs the stack from source (air, `next
  dev`) needs `make generate-docker` after `git pull`: the pull that brings this
  change deletes the committed copies.
