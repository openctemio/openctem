### Changed: the web console downloads only the active language's text

- Every page carried both message catalogs (English and Vietnamese, about
  780 KB gzipped together) in its first-load JavaScript. A page now loads only
  its own language's catalog, on demand and cached by the browser: median
  first-load JavaScript per page fell from 1235 KB to 455 KB gzipped (the
  heaviest, /scans, from 1648 KB to 869 KB), plus about 380 to 410 KB for the
  one catalog.
- Web CI checks first-load JavaScript per page after the production build
  (`web/scripts/route-js-budget.mjs`, budget in `web/scripts/route-js-budget.json`).
