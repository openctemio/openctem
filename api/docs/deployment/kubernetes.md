# Kubernetes

Install OpenCTEM on Kubernetes with the Helm chart in
[openctemio/helm-charts](https://github.com/openctemio/helm-charts); the operator
guide is at [docs.openctem.io/install](https://docs.openctem.io/install/). Do not
hand-write manifests from this repository: the chart carries the database roles,
migration ordering, probes and security contexts that the API expects.

This page lists what the API requires from any Kubernetes deployment, for
developers who change those requirements (update the chart in the same release).

## What the API expects

| Requirement | Detail |
|---|---|
| Images | `ghcr.io/openctemio/openctem-api`, `openctem-web` and `migrations`, all at the same `vX.Y.Z` |
| Migrations first | The API never migrates in production and refuses to start while the schema is behind (`cmd/server/schema_check.go`). Run the `migrations` image to completion (a Job or an init container) before rolling the API. See [Safe Deploy & Migrations](safe-deploy-and-migrations.md). |
| Database roles | The API connects as the DML-only `openctem_app` role, migrations run as `openctem_migrator`. See [Least-privilege database roles](database-roles.md). |
| Secrets | `AUTH_JWT_SECRET` (at least 64 characters), `APP_ENCRYPTION_KEY` (`openssl rand -hex 32`, see [key rotation](encryption-key-rotation.md)), database and Redis passwords |
| Ports | API 8080 (HTTP), 9090 (gRPC); web 3000 |
| Probes | Liveness `GET /health`, readiness `GET /ready` (checks the database and Redis). `/metrics` needs the `METRICS_TOKEN` bearer token. |
| Routing | `/api/*` (including the `/api/v1/ws` WebSocket) to the API, everything else to the web console |
| State | Stateless pods; PostgreSQL 17 and Redis 7 run outside the API Deployment (managed services recommended) |

## Related

- [Docker (development)](docker.md)
- [Monitoring and alerting](../operations/monitoring.md)
