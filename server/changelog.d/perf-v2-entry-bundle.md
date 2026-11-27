### Changed: lighter first download for sign-in and list pages

- Pages now download only the shared parts they use. Before, a page that used one part of a shared component group (one badge, the page header) also downloaded every other part, such as the data table, the filter kit and the detail sheets. The web's `package.json` now declares which modules must run just by being imported (style sheets, the finding-layout registration, the instrumentation and extension entry points), so the bundler can leave out the unused parts. Median first-load script per page: 485 KB down to about 418 KB (gzip).
- Pages without the app shell (sign-in, sign-up, password and e-mail links, two-factor, invitations) load the footer's language menu after the page shows. Until then the same Language button stands in its place. Route-link tabs (legal pages, section tabs) no longer download the tabs component.
- The first-load budget (`web/scripts/route-js-budget.json`) is back to a 480 KB median.
- Docs: none (no behaviour change; the bundle rules are in web/src/lib/__tests__/bundle-boundaries.test.ts)
