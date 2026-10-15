### Added: the product brand is configuration

- `BRAND_NAME`, `BRAND_SHORT_NAME`, `BRAND_PRIMARY_COLOR`, the documentation,
  website, support, terms and privacy links, `BRAND_SUPPORT_EMAIL`,
  `BRAND_EMAIL_FOOTER`, `BRAND_POWERED_BY` and the logo and favicon files
  (`BRAND_LOGO_LIGHT_FILE`, `BRAND_LOGO_DARK_FILE`, `BRAND_FAVICON_FILE`), or
  one YAML `BRAND_FILE`, set the brand users see. Unset, everything stays
  OpenCTEM.
- Public `GET /api/v1/brand` and `GET /api/v1/brand/assets/{kind}` serve it to
  the sign-in page and the console.
- Every value is checked at startup: https-only links, a bare email address,
  `#rrggbb`, names without markup; images at most 512 KiB, identified by
  content (PNG, JPEG, WebP, ICO, SVG), SVG rebuilt from drawing elements and
  refused when it carries script, event handlers or external references. An
  invalid brand stops the API from starting.

### Behaviour change: emails and authenticator apps name the brand, not `APP_NAME`

- Emails and the two-factor issuer label now use `BRAND_NAME` (default
  `OpenCTEM`). `APP_NAME` names the service in logs only. Installations that
  set `APP_NAME` to rename the product set `BRAND_NAME` instead.
