# Console Playwright suite

End-to-end checks of the platform console (`web/console`). The console is its own
Next.js app on its own site, so the suite has its own config
(`web/playwright.console.config.ts`), its own specs (this directory) and its own
workflow (`.github/workflows/console-e2e.yml`). The tenant app's suite
(`web/e2e`) never visits the console, and these specs never run in it.

## What it checks

`specs/pages.spec.ts`: every console page, at 1440x900 and 390x844, signed in and
elevated.

- Routes come from the app directory (every `page.tsx` under
  `src/app/(console)`) and from `src/features/admin-console/config/admin-nav.ts`.
  A new page is visited the day it is added; a moved page is followed without
  editing the spec. Every nav entry must have a page file. A page with a path
  parameter (`organizations/[tenantId]`, `users/[userId]`) must be listed in
  `DETAIL_ROUTES` (`helpers/routes.ts`, opened on the first row of its list), or the
  suite fails: no page goes unvisited.
- Per page: it renders (no error boundary, page error or console error), one `h1`,
  no horizontal scroll, axe-core WCAG 2.2 AA with no critical or serious violation
  on the whole page, no " · " and no em dash in the visible text, and the page
  anatomy of the tenant app's suite (`web/e2e/helpers/page-anatomy.ts`, shared with
  `web/e2e/specs/31-page-rhythm.spec.ts`: PageStack, block gaps, one tab row, metric
  strips, chips, no sideways scroll).

`specs/elevation.spec.ts`: read-only, elevate with a reason and a fresh authenticator
code, then a protected page renders its content.

## Run it locally

You need Postgres and Redis, the API binaries, and the console built.

```bash
# 1. scratch Postgres and Redis (random passwords, loopback only)
docker run -d --name console-e2e-pg -p 127.0.0.1:55432:5432 -e POSTGRES_USER=openctem \
  -e POSTGRES_PASSWORD=<pw> -e POSTGRES_DB=openctem postgres:17-alpine
docker run -d --name console-e2e-redis -p 127.0.0.1:56379:6379 redis:7-alpine

# 2. binaries and console
make generate
BIN=$PWD/.console-e2e-bin; mkdir -p $BIN
go -C server build -o $BIN/server ./cmd/server
go -C server build -o $BIN/openctem-migrate ./cmd/openctem-migrate
ln -sf server $BIN/bootstrap-admin
npm --prefix web run build:console

# 3. stack and administrator (ports and passwords as in step 1)
DB_PORT=55432 DB_PASSWORD=<pw> REDIS_PORT=56379 BIN_DIR=$BIN STACK_DIR=$PWD/.console-e2e \
  bash web/console/e2e/scripts/start-stack.sh
set -a; . .console-e2e/env; set +a

# 4. the suite
cd web && npx playwright test -c playwright.console.config.ts

# 5. clean up
STACK_DIR=$PWD/.console-e2e bash web/console/e2e/scripts/stop-stack.sh   # from the repo root
docker rm -f -v console-e2e-pg console-e2e-redis
```

`start-stack.sh` runs the migrations, starts the API (main listener and console
listener) and `next start console`, and creates a platform administrator with
`bootstrap-admin`. The global setup (`global-setup.ts`) signs that administrator in
through the console's own pages and enrols its authenticator: the secret comes back
in the sign-in answer and is kept, with the new password, under
`web/.console-e2e-auth/` for the specs that need a fresh code. To reuse an
administrator that is already enrolled, set `CONSOLE_E2E_TOTP_SECRET`.

A code is single use and the API accepts a step once, so the specs ask `freshTotp`
for the next 30 second step when the current one was used: a run waits up to a
minute in total.

## CI

`console-e2e.yml` builds the API and the console in the job, uses Postgres and Redis
service containers, and listens on `127.0.0.1` of the job only. Every secret is
random per run (nothing real, nothing stored). It runs on a pull request that
changes `web/console`, the shared page checks or the suite, every night on
`develop`, and on demand; it is not a required check.
