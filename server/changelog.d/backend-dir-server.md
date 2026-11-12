### Changed: the Go backend directory is server/ (source layout only)

- The Go backend directory is now `server/` (it was `api`), and its Go module path is `github.com/openctemio/openctem/server`. URL paths (`/api/v1`, `/api/v2/sensor`, `/api/v3/sensor`), image names, environment variables, configuration, the database and the public API contract are unchanged: operators, sensors and API clients need no action.
- Contributors: on a branch from before the move, run `bash scripts/rename/catch-up.sh`.
- **Upgrade note:** installs from the published images or release archives need no change. If you build from source or vendor files from this repository, use the new paths: `server/` for Go commands, `make -C server ...`, the Dockerfiles under `server/`, the deployment files under `server/deploy/` (compose, gateway, least-privilege SQL) and the module `github.com/openctemio/openctem/server` for Go imports. Release tags up to v0.21.x keep `api/`.
- Docs: server/docs/development/repositories.md
