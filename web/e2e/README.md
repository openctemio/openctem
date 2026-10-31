# Web Console End-to-End Tests

This directory contains [Playwright](https://playwright.dev/) end-to-end
tests that exercise the running stack (UI + API + database) through real
browser interactions. They are intentionally kept separate from the
Vitest unit suite under `src/`.

## Why a separate suite?

The unit tests under `src/` mock the API and run against a virtual DOM
(`jsdom`). They are fast but cannot catch:

- Route protection regressions (cookies, redirects, middleware)
- Auth + multi-tenant context handoff
- API + UI contract mismatches (a backend rename that breaks the
  frontend would compile and unit-test fine but blow up in the browser)
- Real navigation flows that depend on cookies, SWR cache, and form
  state at the same time

These E2E tests address those gaps with a small, high-signal set of
tests that cover the console's most user-visible flows.

## Specs

| Spec file (`specs/`)                        | What it covers                                                                           |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `01-login-and-invitation.spec.ts`           | Login form rejection, successful login, invitation preview                               |
| `02-asset-relationship-multiselect.spec.ts` | Asset list, relationships tab, multi-select picker                                       |
| `03-tag-crud.spec.ts`                       | Add and remove tags from an asset                                                        |
| `04-findings-asset-filter.spec.ts`          | `?assetId=` filter on /findings                                                          |
| `05-owner-picker.spec.ts`                   | Asset owner picker open + search                                                         |
| `07-finding-drawer-writes-once.spec.ts`     | Finding drawer saves each change once                                                    |
| `07-sensor-row-actions.spec.ts`             | Sensor list row actions                                                                  |
| `08-finding-detail-header.spec.ts`          | Finding detail page header                                                               |
| `09-landmarks-and-names.spec.ts`            | Page landmarks and accessible names                                                      |
| `10-scan-detail-runs.spec.ts`               | Scan detail and its runs                                                                 |
| `11-settings-access.spec.ts`                | Settings pages respect permissions                                                       |
| `12-settings-reachability.spec.ts`          | Every settings page is reachable                                                         |
| `13-validation-reachability.spec.ts`        | Validation pages are reachable                                                           |
| `14-remediation-campaigns.spec.ts`          | Remediation campaign list and detail                                                     |
| `15-route-protection.spec.ts`               | Signed-out redirects and public routes                                                   |
| `16-dialog-layout.spec.ts`                  | Dialog header and actions stay put while the body scrolls                                |
| `18-pentest-finding-editor.spec.ts`         | Pentest finding: evidence, publish, closed campaign, edit at 375px                       |
| `19-scan-lifecycle.spec.ts`                 | Scan create, edit (name, targets, duration), run, run view                               |
| `20-sensor-tool-settings-drawer.spec.ts`    | Expanded tool settings stay reachable in the sensor drawer                               |
| `21-remediation-task-from-findings.spec.ts` | Create a task from findings, open it, hold and resume it                                 |
| `23-findings-selection.spec.ts`             | Findings list selection resets; phone card checkbox and menu                             |
| `24-findings-states.spec.ts`                | Findings list: inline error, no access, nothing yet, no match                            |
| `25-findings-quick-views.spec.ts`           | Sidebar quick views under Findings, counts, links                                        |
| `26-findings-filters.spec.ts`               | Add filter, chips, unknown filter, pass-through filters                                  |
| `27-dashboard-header-phone.spec.ts`         | Dashboard header: one toolbar row at 390px and at 1440px                                 |
| `28-dashboard-edit-chrome.spec.ts`          | Dashboard edit mode: widget headers fit at 1440px and 390px                              |
| `29-dashboard-add-widget-sheet.spec.ts`     | Add a widget sheet: nothing past its edges, one-row tabs                                 |
| `30-drawer-text-layout.spec.ts`             | Drawers: no word broken over two lines, one size per meta line, nothing under 12px       |
| `30-finding-detail-requests.spec.ts`        | Finding page: one read per resource, no connector list for other tools                   |
| `30-findings-triage-and-views.spec.ts`      | Triage button opens triage mode, always-on Priority, columns in the URL                  |
| `31-assets-quick-views.spec.ts`             | Sidebar quick views under Assets (lenses), no lens/type pills                            |
| `31-page-rhythm.spec.ts`                    | Page block gaps are the spacing tokens; metric strip rules                               |
| `32-assets-filters.spec.ts`                 | Asset Add filter, chips, no eager tag or business-unit load                              |
| `33-ticketing-connection-errors.spec.ts`    | A failed ticketing connection is worded from its code, offers the fix, shows no id       |
| `34-scans-list-layout.spec.ts`              | Scan list at 390px and 1440px: no overlapping text, state on the title line              |
| `35-assets-row-anatomy.spec.ts`             | Asset rows at 1920px: one height, type line, a time; axe; no h-scroll at 375px           |
| `36-findings-triage-mode.spec.ts`           | Triage mode: keys-only session over ten findings, request budget, a11y, Exit             |
| `36-list-toolbar.spec.ts`                   | One list toolbar: search first, joined filter trigger, `/` and Escape, phone width, axe  |
| `37-pentest-template-editor.spec.ts`        | Finding-library template: create, then edit at 375px                                     |
| `38-assets-vocabulary.spec.ts`              | Asset criticality vs risk wording, one-line phone card, open findings count              |
| `39-assets-list-states.spec.ts`             | Asset search keeps typed keys, toolbar on error, last page, empty default list           |
| `40-filter-chips-row-phone.spec.ts`         | Filter chips row at 390/375px: locked chip and chips never overlap, search on its line   |
| `41-assets-service-facts.spec.ts`           | Asset service facts: whole chips and +N at 1280/1440/1920, no table side-scroll, axe     |
| `43-new-scan-review-coverage.spec.ts`       | New Scan review: skipped targets by reason, neutral, searchable, 1440/390px, axe         |
| `44-ctem-scope-to-inventory.spec.ts`        | Scope a domain, one asset per name, URL text never widens scope, exclusions              |
| Spec file (`specs/`)                        | What it covers                                                                           |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `01-login-and-invitation.spec.ts`           | Login form rejection, successful login, invitation preview                               |
| `02-asset-relationship-multiselect.spec.ts` | Asset list, relationships tab, multi-select picker                                       |
| `03-tag-crud.spec.ts`                       | Add and remove tags from an asset                                                        |
| `04-findings-asset-filter.spec.ts`          | `?assetId=` filter on /findings                                                          |
| `05-owner-picker.spec.ts`                   | Asset owner picker open + search                                                         |
| `07-finding-drawer-writes-once.spec.ts`     | Finding drawer saves each change once                                                    |
| `07-sensor-row-actions.spec.ts`             | Sensor list row actions                                                                  |
| `08-finding-detail-header.spec.ts`          | Finding detail page header                                                               |
| `09-landmarks-and-names.spec.ts`            | Page landmarks and accessible names                                                      |
| `10-scan-detail-runs.spec.ts`               | Scan detail and its runs                                                                 |
| `11-settings-access.spec.ts`                | Settings pages respect permissions                                                       |
| `12-settings-reachability.spec.ts`          | Every settings page is reachable                                                         |
| `13-validation-reachability.spec.ts`        | Validation pages are reachable                                                           |
| `14-remediation-campaigns.spec.ts`          | Remediation campaign list and detail                                                     |
| `15-route-protection.spec.ts`               | Signed-out redirects and public routes                                                   |
| `16-dialog-layout.spec.ts`                  | Dialog header and actions stay put while the body scrolls                                |
| `18-pentest-finding-editor.spec.ts`         | Pentest finding: evidence, publish, closed campaign, edit at 375px                       |
| `19-scan-lifecycle.spec.ts`                 | Scan create, edit (name, targets, duration), run, run view                               |
| `20-sensor-tool-settings-drawer.spec.ts`    | Expanded tool settings stay reachable in the sensor drawer                               |
| `21-remediation-task-from-findings.spec.ts` | Create a task from findings, open it, hold and resume it                                 |
| `23-findings-selection.spec.ts`             | Findings list selection resets; phone card checkbox and menu                             |
| `24-findings-states.spec.ts`                | Findings list: inline error, no access, nothing yet, no match                            |
| `25-findings-quick-views.spec.ts`           | Sidebar quick views under Findings, counts, links                                        |
| `26-findings-filters.spec.ts`               | Add filter, chips, unknown filter, pass-through filters                                  |
| `27-dashboard-header-phone.spec.ts`         | Dashboard header: one toolbar row at 390px and at 1440px                                 |
| `28-dashboard-edit-chrome.spec.ts`          | Dashboard edit mode: widget headers fit at 1440px and 390px                              |
| `29-dashboard-add-widget-sheet.spec.ts`     | Add a widget sheet: nothing past its edges, one-row tabs                                 |
| `30-drawer-text-layout.spec.ts`             | Drawers: no word broken over two lines, one size per meta line, nothing under 12px       |
| `30-finding-detail-requests.spec.ts`        | Finding page: one read per resource, no connector list for other tools                   |
| `30-findings-triage-and-views.spec.ts`      | Triage button opens triage mode, always-on Priority, columns in the URL                  |
| `31-assets-quick-views.spec.ts`             | Sidebar quick views under Assets (lenses), no lens/type pills                            |
| `31-page-rhythm.spec.ts`                    | Page block gaps are the spacing tokens; metric strip rules                               |
| `32-assets-filters.spec.ts`                 | Asset Add filter, chips, no eager tag or business-unit load                              |
| `33-ticketing-connection-errors.spec.ts`    | A failed ticketing connection is worded from its code, offers the fix, shows no id       |
| `34-scans-list-layout.spec.ts`              | Scan list at 390px and 1440px: no overlapping text, state on the title line              |
| `35-assets-row-anatomy.spec.ts`             | Asset rows: one height, type line, a time; axe; no h-scroll at 375px                     |
| `36-findings-triage-mode.spec.ts`           | Triage mode: keys-only session over ten findings, request budget, a11y, Exit             |
| `36-list-toolbar.spec.ts`                   | One list toolbar: search first, joined filter trigger, `/` and Escape, phone width, axe  |
| `37-pentest-template-editor.spec.ts`        | Finding-library template: create, then edit at 375px                                     |
| `38-assets-vocabulary.spec.ts`              | Asset criticality vs risk wording, one-line phone card, open findings count              |
| `39-assets-list-states.spec.ts`             | Asset search keeps typed keys, toolbar on error, last page, empty default list           |
| `40-filter-chips-row-phone.spec.ts`         | Filter chips row at 390/375px: locked chip and chips never overlap, search on its line   |
| `41-attack-path-canvas.spec.ts`             | Attack path canvas at 1440px (zoom 1, keys, hover, axe), list view at 390px, error state |
| `44-vulnerabilities-list.spec.ts`           | Vulnerabilities list: rows, strip filters, parity with findings, Back, 390px, axe        |
| Spec file (`specs/`)                        | What it covers                                                                           |
| ------------------------------------------- | ---------------------------------------------------------------------------------------  |
| `01-login-and-invitation.spec.ts`           | Login form rejection, successful login, invitation preview                               |
| `02-asset-relationship-multiselect.spec.ts` | Asset list, relationships tab, multi-select picker                                       |
| `03-tag-crud.spec.ts`                       | Add and remove tags from an asset                                                        |
| `04-findings-asset-filter.spec.ts`          | `?assetId=` filter on /findings                                                          |
| `05-owner-picker.spec.ts`                   | Asset owner picker open + search                                                         |
| `07-finding-drawer-writes-once.spec.ts`     | Finding drawer saves each change once                                                    |
| `07-sensor-row-actions.spec.ts`             | Sensor list row actions                                                                  |
| `08-finding-detail-header.spec.ts`          | Finding detail page header                                                               |
| `09-landmarks-and-names.spec.ts`            | Page landmarks and accessible names                                                      |
| `10-scan-detail-runs.spec.ts`               | Scan detail and its runs                                                                 |
| `11-settings-access.spec.ts`                | Settings pages respect permissions                                                       |
| `12-settings-reachability.spec.ts`          | Every settings page is reachable                                                         |
| `13-validation-reachability.spec.ts`        | Validation pages are reachable                                                           |
| `14-remediation-campaigns.spec.ts`          | Remediation campaign list and detail                                                     |
| `15-route-protection.spec.ts`               | Signed-out redirects and public routes                                                   |
| `16-dialog-layout.spec.ts`                  | Dialog header and actions stay put while the body scrolls                                |
| `18-pentest-finding-editor.spec.ts`         | Pentest finding: evidence, publish, closed campaign, edit at 375px                       |
| `19-scan-lifecycle.spec.ts`                 | Scan create, edit (name, targets, duration), run, run view                               |
| `20-sensor-tool-settings-drawer.spec.ts`    | Expanded tool settings stay reachable in the sensor drawer                               |
| `21-remediation-task-from-findings.spec.ts` | Create a task from findings, open it, hold and resume it                                 |
| `23-findings-selection.spec.ts`             | Findings list selection resets; phone card checkbox and menu                             |
| `24-findings-states.spec.ts`                | Findings list: inline error, no access, nothing yet, no match                            |
| `25-findings-quick-views.spec.ts`           | Sidebar quick views under Findings, counts, links                                        |
| `26-findings-filters.spec.ts`               | Add filter, chips, unknown filter, pass-through filters                                  |
| `27-dashboard-header-phone.spec.ts`         | Dashboard header: one toolbar row at 390px and at 1440px                                 |
| `28-dashboard-edit-chrome.spec.ts`          | Dashboard edit mode: widget headers fit at 1440px and 390px                              |
| `29-dashboard-add-widget-sheet.spec.ts`     | Add a widget sheet: nothing past its edges, one-row tabs                                 |
| `30-drawer-text-layout.spec.ts`             | Drawers: no word broken over two lines, one size per meta line, nothing under 12px       |
| `30-finding-detail-requests.spec.ts`        | Finding page: one read per resource, no connector list for other tools                   |
| `30-findings-triage-and-views.spec.ts`      | Triage button opens triage mode, always-on Priority, columns in the URL                  |
| `31-assets-quick-views.spec.ts`             | Sidebar quick views under Assets (lenses), no lens/type pills                            |
| `31-page-rhythm.spec.ts`                    | Page block gaps are the spacing tokens; metric strip rules                               |
| `32-assets-filters.spec.ts`                 | Asset Add filter, chips, no eager tag or business-unit load                              |
| `33-ticketing-connection-errors.spec.ts`    | A failed ticketing connection is worded from its code, offers the fix, shows no id       |
| `34-scans-list-layout.spec.ts`              | Scan list at 390px and 1440px: no overlapping text, state on the title line              |
| `35-assets-row-anatomy.spec.ts`             | Asset rows at 1920px: one height, type line, a time; axe; no h-scroll at 375px           |
| `36-findings-triage-mode.spec.ts`           | Triage mode: keys-only session over ten findings, request budget, a11y, Exit             |
| `36-list-toolbar.spec.ts`                   | One list toolbar: search first, joined filter trigger, `/` and Escape, phone width, axe  |
| `37-pentest-template-editor.spec.ts`        | Finding-library template: create, then edit at 375px                                     |
| `38-assets-vocabulary.spec.ts`              | Asset criticality vs risk wording, one-line phone card, open findings count              |
| `39-assets-list-states.spec.ts`             | Asset search keeps typed keys, toolbar on error, last page, empty default list           |
| `40-filter-chips-row-phone.spec.ts`         | Filter chips row at 390/375px: locked chip and chips never overlap, search on its line   |
| `41-assets-service-facts.spec.ts`           | Asset service facts: whole chips and +N at 1280/1440/1920, no table side-scroll, axe     |
| `43-new-scan-review-coverage.spec.ts`       | New Scan review: skipped targets by reason, neutral, searchable, 1440/390px, axe         |
| `44-scan-targets-step.spec.ts`              | Targets step at 390/1440px: one footer row, Next gated with its reason, ranked fixes     |
| `44-sidebar-phone-drawer.spec.ts`           | Phone sidebar drawer: one scroller, one filled row, rows hold still, footer never clips  |
| `50-finding-detail-no-shift.spec.ts`        | Finding page: no layout shift while its bands and side panels load (390px, 1440px)       |
| `51-dashboard-editor-actions.spec.ts`       | Dashboard + editor toolbars fit at 390/1440px, sticky editor bar, added widget focused   |
| `51-sidebar-footer-pinned.spec.ts`          | Settings and Help stay at the sidebar bottom while the nav scrolls (desktop, phone)      |
| `50-shell-banner-no-shift.spec.ts`           | A platform notice does not push the page down on reload (390px)                          |
| `50-shell-banner-no-shift.spec.ts`          | A platform notice does not push the page down on reload (390px)                          |
| `51-cicd-settings.spec.ts`                  | CI/CD Settings: every section on one page, `?section=` scrolls, 1440/390px, axe, budget  |
| `52-cicd-lists.spec.ts`                     | CI/CD Pipelines and Runs at 1440/390px: no sideways scroll, axe, request budget          |
| `50-shell-banner-no-shift.spec.ts`          | A platform notice does not push the page down on reload (390px)                          |
| `50-metric-strip-no-shift.spec.ts`          | Metric strips and /attack-surface hold still while their numbers load (1440, 390)        |
| `50-asset-detail-no-shift.spec.ts`          | Asset page: no layout shift while its panels load (390px, 1440px)                        |
| `52-team-outside-members.spec.ts`          | A team with outside members turns full-data roles off up front and names them (390px too) |
| `53-asset-discovery-lineage.spec.ts`       | Asset page: how a subdomain was found (chain, link to its domain), 1280/390px, no sideways scroll |

Each spec is designed to:

- **Skip gracefully** when prerequisites are missing (no env, no seed
  data) so the suite stays green on a fresh clone.
- **Avoid hard-coded copy** in favour of role/label selectors so the
  tests survive UI tweaks and i18n.
- **Document its TODOs** — every spec ends with a comment block listing
  the deeper assertions that should be added once the relevant
  data-testid hooks or API helpers exist.

## Setup

1. Install Playwright browsers (first time only):

   ```bash
   npm run e2e:install
   ```

2. Copy the env template and fill in real credentials:

   ```bash
   cp e2e/.env.example e2e/.env
   $EDITOR e2e/.env
   ```

   You need at minimum:
   - `E2E_USER_EMAIL` — seed admin/owner user
   - `E2E_USER_PASSWORD` — that user's password
   - `E2E_TENANT_SLUG` — slug of the tenant they belong to

   Optional:
   - `E2E_BASE_URL` — defaults to `http://localhost:3000`
   - `E2E_API_BASE_URL` — for tests that hit the API directly
   - `E2E_LOCALE` — override the browser locale (defaults to `en-US`)

3. Make sure the web app and API are running (monorepo: `api/` and `web/`):

   ```bash
   # in api/
   make dev

   # in web/
   npm run dev
   ```

   One account drives every test, so raise the API's per-user read limit
   for the stack under test (`RATE_LIMIT_READ_PER_MIN=3000`). At the default
   of 120 reads a minute the parallel run gets 429s and their error toasts
   cover the menus the tests click.

### Sign-in

Each worker signs in once (`fixtures/authenticated-page.ts`, a worker-scoped
fixture) and every test in that worker reuses the saved session through
`storageState`. Signing in per test hit the API's sign-in limit (5 a minute
per address). One session per worker, not one shared by all workers, keeps
refresh-token rotation inside one process. A refused sign-in waits for the
limit window and retries.

## Running

```bash
npm run e2e               # headless run, all specs
npm run e2e:headed        # show the browser as it runs
npm run e2e:ui            # interactive Playwright UI runner
npm run e2e:report        # open the most recent HTML report
```

The request budget spec (`16-request-budget.spec.ts`, budgets in
`request-budget.json`) loads every dashboard page. While changing one page,
check only that page with `E2E_BUDGET_ROUTES=/ npx playwright test
e2e/specs/16-request-budget.spec.ts` (comma-separated routes); CI always
checks every page.

By default the suite uses Chromium only. Tests tagged `@phone` also run on
WebKit with an iPhone 13 viewport when `E2E_WEBKIT=1` is set (install it
once with `npx playwright install --with-deps webkit`):

```bash
E2E_WEBKIT=1 npx playwright test --project=webkit-mobile --workers=1
```

## Layout

```
e2e/
├── README.md                       # this file
├── .env.example                    # copy to .env and fill in
├── fixtures/
│   └── authenticated-page.ts       # custom test fixture (logged-in page)
├── helpers/
│   ├── assets.ts                   # openFirstAssetSheet()
│   ├── auth.ts                     # loginAs(), gotoDashboardPath()
│   ├── env.ts                      # env loading + skip-on-missing
│   └── table.ts                    # dataRows(), firstDataRow()
├── ci/                             # CI stack: compose.yml, make-env.sh, seed.sh
└── specs/                          # NN-name.spec.ts, see the table above
```

## Writing new tests

Use the authenticated fixture for any test that needs a logged-in
session:

```ts
import { test, expect } from '../fixtures/authenticated-page'

test('my new flow', async ({ page, e2eConfig }) => {
  await page.goto('/some-page')
  // ...
})
```

For tests that exercise unauthenticated flows (login, register, public
invitation preview) import `test` from `@playwright/test` directly.

### Tag every test

CI runs only the specs a change needs. Each test (or its enclosing
`test.describe`) declares an area tag with Playwright's tag option:

```ts
test.describe('Findings list', { tag: ['@findings'] }, () => { ... })
test('sign in', { tag: ['@auth', '@smoke'] }, async ({ page }) => { ... })
```

- Area tags are the ones under `tags` in `impact-map.yml` (`@findings`,
  `@assets`, `@scans`, ...). A spec that crosses areas lists several.
- `@smoke` joins the set that runs with every change (keep it to about eight
  specs that prove the app works), `@serial` marks a spec that cannot share a
  worker, `@budget` the every-page request budget check.
- A new feature area also needs its paths under `areas` in
  `web/e2e/impact-map.yml`; a path nobody mapped makes CI run every spec.
- `node e2e/ci/select.mjs check` (from `web/`) is the gate Web CI runs: it
  fails on an untagged test. `node --test e2e/ci/select.test.mjs` runs the
  selector's tests. Locally, `npx playwright test --grep @findings` runs one area.

### Selector guidelines

- **Prefer roles and accessible names** (`getByRole`, `getByLabel`).
- **Avoid CSS class selectors** — they break on Tailwind/CVA refactors.
- **Use `data-testid`** when there is no semantic alternative, and add
  the attribute on the source component in the same PR.
- **Use regular expressions** for any user-facing text so the test
  survives small copy changes and basic localisation.

### Skipping gracefully

When a test depends on seed data that may not be present, use:

```ts
const row = await firstDataRow(page)
test.skip(!row, 'Need at least one X — seed it to enable this test')
```

Do not use `getByRole('row').nth(1)` for "the first row": an empty table
renders one full-width "No ... yet" row, which is visible and is not data.
`dataRows()` / `firstDataRow()` in `helpers/table.ts` match rows with at
least two cells.

This keeps the suite useful as a smoke test on a fresh tenant while
giving teams with seed data the full coverage.

## Troubleshooting

- **All tests skip with "missing env vars"** — copy `e2e/.env.example`
  to `e2e/.env`.
- **Login times out** — check that the API is actually running on the
  port your `E2E_BASE_URL` points to and that the seed user can log in
  manually in a real browser.
- **"No assets in tenant"** — most tests need at least one asset; seed
  one via the API or the UI before running.
- **Random 429s, toasts covering menus** — raise `RATE_LIMIT_READ_PER_MIN`
  on the API under test (see Setup).
- **A sign-in pauses for up to a minute** — expected. The API allows 5
  sign-ins a minute per address, and the suite makes more than that from
  one address. Sign in through `submitSignIn` / `loginAs` in
  `helpers/auth.ts`: on "Rate limit exceeded" they wait for the window and
  submit again, instead of timing out.
- **Tests pass locally, fail in CI** — bump `workers: 1` in
  `playwright.config.ts` (already the default for `CI=true`) and check
  for tests that depend on shared state.

## CI integration

`.github/workflows/web-e2e.yml` runs the suite on pull requests and in the
merge queue when `web/` (or a shared file) changed — the routing is
`.github/scripts/changed.sh`, so an API-only change does not start it. A pull
request or queue group runs the specs its changed files map to (plus the
`@smoke` set), split into 1 to 4 shards; a push to `develop` and the nightly run
run all of them. See [E2E impact selection](../../api/docs/development/ci-cd.md#e2e-impact-selection).

The job builds the production images (API, web) with the Actions
layer cache, generates the stack's secrets (`e2e/ci/make-env.sh`), starts `e2e/ci/compose.yml` (Postgres, Redis, migrations, API
with `RATE_LIMIT_READ_PER_MIN=3000`, web), seeds a tenant with
`e2e/ci/seed.sh` (owner, assets, two sensors, 15 findings, a remediation
task) and runs `npm run e2e` with `CI=true`. On failure it uploads
`playwright-report/`, `test-results/` and the API and web logs.

The same stack runs locally (move the ports if 3000/8080 are taken):

```bash
docker build -t local/openctem-api:e2e --target production api
docker build -t local/openctem-web:e2e web
bash web/e2e/ci/make-env.sh        # web/e2e/ci/.env: random secrets (git-ignored)
docker compose -f web/e2e/ci/compose.yml up -d --wait
(set -a; . web/e2e/ci/.env; bash web/e2e/ci/seed.sh) > web/e2e/.env
cd web && CI=true npm run e2e
```

No password or secret is written in the repository. `make-env.sh` generates
every one per run (the workflow masks them in the log); `e2e/ci/.env.example`
lists the variable names.
