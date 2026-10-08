# Web Console Developer Documentation

Developer documentation for the web console (`web/`). User and operator
documentation is at [docs.openctem.io](https://docs.openctem.io); platform-wide
engineering docs (API architecture, RFCs, CI/CD) are in
[`api/docs/`](../../api/docs/README.md).

> These docs moved with the web console from `openctemio/ui` (archived) into the
> `openctemio/openctem` monorepo. In older documents a bare `#NNN` may refer to an
> `openctemio/ui` pull request (`openctemio/ui#NNN`), not to this repository.

## Start here

1. [Web console README](../README.md): setup, commands, structure.
2. [Architecture](ARCHITECTURE.md): how the console is built and talks to the API.
3. [Calling the API](guides/API_INTEGRATION.md): client, hooks, mutations, errors.

## Contents

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Request path, authentication flow, data patterns, design system, dashboard header |
| [security-architecture.md](security-architecture.md) | Sessions and cookies, permissions, route protection, CSP, safe links, WebSocket, CSRF |
| [ui-style-contract.md](ui-style-contract.md) | The rules every screen follows: page anatomy, lists, drawers, empty states |
| [finding-detail.md](finding-detail.md) | Finding page and drawer layout |
| [ui/activity-panel.md](ui/activity-panel.md) | Activity and comments panel |
| [nav-coverage.md](nav-coverage.md) | No scaffold pages in the sidebar, and the test that enforces it |
| [guides/API_INTEGRATION.md](guides/API_INTEGRATION.md) | Calling the API from the console |
| [ops/ENVIRONMENT_VARIABLES.md](ops/ENVIRONMENT_VARIABLES.md) | Every environment variable the console reads |
| [ops/DOCKER_SENTRY_SETUP.md](ops/DOCKER_SENTRY_SETUP.md) | Docker files, running in Docker, enabling Sentry |
| [MAKEFILE.md](MAKEFILE.md) | `web/Makefile` targets |
| [../e2e/README.md](../e2e/README.md) | Playwright end-to-end tests |

Coding conventions for contributors and AI assistants are in
[`web/CLAUDE.md`](../CLAUDE.md) and [`web/.claude/`](../.claude/).
