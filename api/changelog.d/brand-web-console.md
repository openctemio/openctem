### Added: the web console follows the instance brand

- The console reads the brand from the API (`GET /api/v1/brand`) on the
  server: the page title, the favicon, the sidebar and sign-in logos (light
  and dark), the primary color, documentation links, the legal contacts'
  defaults and the "Powered by OpenCTEM" credit on the sign-in pages follow
  it. When the API has no brand endpoint or cannot be reached, the console
  stays OpenCTEM.
- Catalog strings name the product through `{product}`; a web test fails on
  a new hard-coded product name in user-visible text.

### Removed: `NEXT_PUBLIC_APP_NAME`

- The page title now comes from `BRAND_NAME` on the API; the web variable is
  no longer read.
