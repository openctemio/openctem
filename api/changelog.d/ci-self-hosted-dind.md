### Fixed: CI jobs pass on the self-hosted runners

- The gateway smoke test copies the Caddyfile and its test certificate into Docker volumes instead of bind-mounting the checkout, which a runner's separate Docker-in-Docker daemon cannot see (every gateway check failed there with status 000).
- Every PostgreSQL health check in CI names its user and database (`pg_isready -U ... -d ...`), so the service log no longer shows `role "root" does not exist`.
- CodeQL sets up Node.js before the JavaScript/TypeScript analysis, which the self-hosted runner image does not ship.
- `api/docs/development/ci-cd.md` lists the rules for jobs that may run on a self-hosted runner.
- The production compose render check installs its pinned `yq` when the runner has none.
