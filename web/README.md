# OpenCTEM Web Console

The web console of OpenCTEM, the open-source Continuous Threat Exposure
Management (CTEM) platform. It covers the five CTEM stages: Scoping, Discovery,
Prioritization, Validation and Mobilization.

This is `web/` in the [`openctemio/openctem`](https://github.com/openctemio/openctem)
monorepo (formerly the `openctemio/ui` repository, now archived); the Go API it
talks to is [`../api/`](../api/). User documentation is at
[docs.openctem.io](https://docs.openctem.io).

## Tech stack

| Category  | Technology                                                     |
| --------- | -------------------------------------------------------------- |
| Framework | Next.js 16 (App Router, Turbopack)                             |
| UI        | React 19, TypeScript 5 (strict), shadcn/ui, Tailwind CSS 4     |
| State     | Zustand (auth), React Context (theme, direction, layout)       |
| Data      | SWR (client fetching), Server Components                       |
| Forms     | React Hook Form + Zod                                          |
| Auth      | Local accounts (JWT), OAuth (Google, GitHub, Microsoft), OIDC/Entra ID and SAML SSO through the API |
| i18n      | English and Vietnamese (`supportedLocales` in `src/lib/i18n.ts`) |
| Testing   | Vitest, React Testing Library, Playwright                      |

## Project structure

```
web/src/
├── app/                    # Next.js App Router
│   ├── (auth)/             # Login, register, password reset
│   ├── (dashboard)/        # Signed-in console, grouped by CTEM stage:
│   │   ├── (scoping)/ (discovery)/ (prioritization)/ (validation)/ (mobilization)/
│   │   └── findings/ insights/ reports/ settings/ ...
│   ├── (admin-console)/    # Platform admin console
│   └── api/                # Same-origin API proxy (/api/v1/*) and route handlers
├── features/               # Feature modules (components, hooks, api, types per feature)
├── components/             # Shared components (ui/ = shadcn/ui, layout/)
├── context/                # Theme, direction, layout, permission providers
├── stores/                 # Zustand stores (auth)
├── lib/                    # API client, permissions, utilities
└── hooks/                  # Global hooks
```

Asset type pages (`src/app/(dashboard)/(discovery)/assets/<type>/`) are a
`page.tsx` that renders the shared `AssetPage` with a per-type `AssetPageConfig`
(`config.tsx` next to it; type in `src/features/assets/types/page-config.types.ts`).

## Quick start

From the repository root, `make setup` installs both components, generates the
API contract types and enables the git hooks; `make dev-web` runs this app. The
commands below run in `web/`.

Prerequisites: Node.js 26 (the Docker image builds on `node:26-alpine`) and npm.

```bash
npm ci
cp .env.example .env.local
npm run dev          # http://localhost:3000
```

The generated contract file (`src/lib/api/generated/api.types.ts`) is not
committed; `npm run dev`, `build`, `lint`, `type-check` and `test` check for it
first (`scripts/ensure-generated.mjs`). Generate it with `make generate` at the
repository root.

### Environment variables

```env
# Backend API (required, server-side only; the browser uses the relative
# /api/v1/* proxy, so there is no NEXT_PUBLIC_ API URL)
BACKEND_API_URL=http://localhost:8080

NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_APP_NAME=OpenCTEM

# Forward X-Real-IP / X-Forwarded-For to the API (organization IP allowlists).
# Only set true when a reverse proxy in front of the console overwrites these
# headers; otherwise they are browser-supplied and never forwarded.
TRUST_PROXY_HEADERS=false
```

[`.env.example`](.env.example) is the authoritative list
(`SECURE_COOKIES`, cookie names, Sentry, sidebar badges, ...). Variable details:
[docs/ops/ENVIRONMENT_VARIABLES.md](docs/ops/ENVIRONMENT_VARIABLES.md).

## Commands

```bash
npm run dev            # Dev server (Turbopack, port 3000)
npm run build          # Production build
npm start              # Serve the production build
npm run lint           # ESLint (lint:fix to fix)
npm run type-check     # TypeScript
npm run format         # Prettier (format:check to check)
npm run validate       # type-check + lint + format:check
npm test               # Vitest (test:coverage, test:watch, test:ui)
npm run e2e            # Playwright (see e2e/README.md)
```

## Deployment

The console ships as `ghcr.io/openctemio/openctem-web` and inside the all-in-one
image `ghcr.io/openctemio/openctem`. Install and operate it with the guides at
[docs.openctem.io/install](https://docs.openctem.io/install/).

## Further reading

- [Developer documentation index](docs/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security architecture](docs/security-architecture.md)

## License

GNU General Public License v3.0 (GPL-3.0). See [LICENSE](LICENSE).
