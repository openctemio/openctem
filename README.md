# OpenCTEM

[![API CI](https://github.com/openctemio/openctem/actions/workflows/api-ci.yml/badge.svg?branch=develop)](https://github.com/openctemio/openctem/actions/workflows/api-ci.yml)
[![Web CI](https://github.com/openctemio/openctem/actions/workflows/web-ci.yml/badge.svg?branch=develop)](https://github.com/openctemio/openctem/actions/workflows/web-ci.yml)
[![CodeQL](https://github.com/openctemio/openctem/actions/workflows/codeql.yml/badge.svg?branch=develop)](https://github.com/openctemio/openctem/actions/workflows/codeql.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

Open-source Continuous Threat Exposure Management platform. This repository holds
the two parts that ship together:

| Directory | What | Image |
|---|---|---|
| [`api/`](api/) | Go API server, migrations, admin CLI (module `github.com/openctemio/openctem/api`) | `ghcr.io/openctemio/openctem-api` |
| [`web/`](web/) | Next.js web console | `ghcr.io/openctemio/openctem-web` |
| [`deploy/allinone/`](deploy/allinone/) | API + web + gateway in one container (Postgres/Redis external) | `ghcr.io/openctemio/openctem` |

Released separately, in their own repositories:
[sensor](https://github.com/openctemio/sensor) (runs scans and collectors),
[sdk-go](https://github.com/openctemio/sdk-go),
[ctis](https://github.com/openctemio/ctis) (shared contract),
[helm-charts](https://github.com/openctemio/helm-charts),
[docs](https://github.com/openctemio/docs) (public documentation, published at
[docs.openctem.io](https://docs.openctem.io)).

## Repository layout & history

The monorepo was formed on 2026-10-02
([RFC-020](api/docs/rfcs/RFC-020-api-ui-monorepo.md)):

- **`openctemio/api` → this repository.** It was renamed, so its issues, pull
  requests, releases (v0.1.x–v0.8.0) and old links carry over and redirect here.
  Its Go code moved to `api/`; the module path is now
  `github.com/openctemio/openctem/api`.
- **`openctemio/ui` → `web/`.** Its full history was imported under `web/`, and
  [openctemio/ui](https://github.com/openctemio/ui) is archived (read-only); its
  old releases stay there. Cite its PRs as `openctemio/ui#NNN`: a bare `#NNN`
  means this repository.
- **`ui/vX.Y.Z` tags** are the ui repository's tags, imported for history only.
  They release nothing; only `vX.Y.Z` tags do (see [Releases](#releases)).
- **Images** moved from `ghcr.io/openctemio/api` / `ui` to `openctem-api` /
  `openctem-web`; the old names are mirrored for a transition window.
- `openctemio/agent` had already become [openctemio/sensor](https://github.com/openctemio/sensor) (RFC-023).

More: [repository map](api/docs/development/repositories.md),
[CI/CD and releases](api/docs/development/ci-cd.md).

## Quick start (development)

```bash
make setup     # go mod download, npm ci, enable git hooks
make dev-api   # see api/README.md for Postgres/Redis
make dev-web   # http://localhost:3000
make check     # what CI runs, both components
```

## Deploying

- **Compose, one HTTPS port:** [`api/deploy/docker-compose.yml`](api/deploy/docker-compose.yml)
  runs the gateway ([`api/deploy/gateway`](api/deploy/gateway), Caddy), web, API,
  Postgres and Redis; only the gateway is published.
- **All-in-one image:** `ghcr.io/openctemio/openctem` embeds the same gateway.
  ```bash
  docker run -d -p 443:443 -v openctem-data:/data \
    -e OPENCTEM_HOSTNAME=ctem.example.com -e DB_HOST=... -e DB_PASSWORD=... -e REDIS_HOST=... \
    -e AUTH_JWT_SECRET=... -e APP_ENCRYPTION_KEY=... ghcr.io/openctemio/openctem:vX.Y.Z
  ```
  `GATEWAY=on` (default) serves only :443 (`OPENCTEM_TLS_MODE` internal | acme |
  files | http, as in the Compose gateway); `GATEWAY=off` serves the API on :8080
  and the web on :3000 for your own proxy. `/data` keeps attachments and the
  gateway's CA: mount a volume.
- **Kubernetes:** [helm-charts](https://github.com/openctemio/helm-charts).

Installation, configuration and operations are documented at
[docs.openctem.io/install](https://docs.openctem.io/install/).

## Releases

One tag, `vX.Y.Z`, releases every image from the same commit: `openctem-api`,
`openctem-web`, `openctem` (all-in-one), `migrations`, `seed`, `admin-cli`, all
multi-arch (amd64, arm64), signed with cosign, with SBOMs on the release. The
pre-monorepo names `ghcr.io/openctemio/api` and `ghcr.io/openctemio/ui` keep
receiving identical copies for two releases. See
[`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml).

## The API contract

`api/api/openapi/swagger.yaml` is generated from the Go handler annotations
(gated by `api/scripts/check-openapi.sh`), and the web wire types in
`web/src/lib/api/generated/api.types.ts` are generated from that file. Neither
is committed: run `make generate` after cloning or pulling (`make
generate-docker` needs only Docker). CI type-checks the web against the
contract a pull request produces, so a change to the API contract and the web
code that consumes it land in one pull request, and it posts the contract
changes (breaking changes, route gate changes) on the pull request.

## Documentation

- User and operator documentation: [docs.openctem.io](https://docs.openctem.io)
- Engineering documentation (architecture, development, RFCs): [`api/docs/`](api/docs/README.md)
  and [`web/docs/`](web/docs/README.md)

## Contributing / security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described
in [SECURITY.md](SECURITY.md), never in a public issue.
