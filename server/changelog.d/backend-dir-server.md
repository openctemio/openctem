### Changed: the Go backend directory is server/ (source layout only)

- The Go backend directory is now `server/` (it was `api`), and its Go module path is `github.com/openctemio/openctem/server`. URL paths (`/api/v1`, `/api/v2/sensor`, `/api/v3/sensor`), image names, environment variables, configuration, the database and the public API contract are unchanged: operators, sensors and API clients need no action.
- Contributors: on a branch from before the move, run `bash scripts/rename/catch-up.sh`.
