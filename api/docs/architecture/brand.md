# Product brand

The product name, logos, color and links that people see come from one
configuration, the **instance brand**. A differently named build or a
white-label deployment changes configuration only, never code. The default is
today's OpenCTEM brand, so an installation that sets nothing looks exactly as
before.

Status: the instance brand (configuration, public endpoint, validation) is
shipped. Using it everywhere text names the product is shipped in steps (see
"Where the brand is used"). The per-organization override is **designed only**
(see the last section).

## What is configurable

| Setting | Variable | `BRAND_FILE` key | Default |
|---|---|---|---|
| Product name | `BRAND_NAME` | `name` | `OpenCTEM` |
| Short name (sidebar, browser tab) | `BRAND_SHORT_NAME` | `short_name` | the name |
| Primary color (`#rrggbb`) | `BRAND_PRIMARY_COLOR` | `primary_color` | the theme color |
| Documentation site | `BRAND_DOCS_URL` | `docs_url` | `https://docs.openctem.io` |
| Website | `BRAND_WEBSITE_URL` | `website_url` | `https://openctem.io` |
| Support page | `BRAND_SUPPORT_URL` | `support_url` | none |
| Support email | `BRAND_SUPPORT_EMAIL` | `support_email` | `info@openctem.io` |
| Terms of service | `BRAND_TERMS_URL` | `terms_url` | none |
| Privacy policy | `BRAND_PRIVACY_URL` | `privacy_url` | none |
| Email footer line | `BRAND_EMAIL_FOOTER` | `email_footer` | none |
| "Powered by OpenCTEM" credit | `BRAND_POWERED_BY` | `powered_by` | `true` (shown only when the name is not OpenCTEM) |
| Logo, light background | `BRAND_LOGO_LIGHT_FILE` | `logo_light_file` | built-in mark |
| Logo, dark background | `BRAND_LOGO_DARK_FILE` | `logo_dark_file` | the light logo |
| Browser tab icon | `BRAND_FAVICON_FILE` | `favicon_file` | built-in icon |

`BRAND_FILE` is an optional YAML file with the keys above (unknown keys are
refused; at most 64 KiB). Image paths in it are relative to the file. A
`BRAND_*` variable wins over the file. Example:

```yaml
name: Example Exposure
short_name: Example
primary_color: "#0a7b83"
docs_url: https://docs.example.com
support_email: support@example.com
email_footer: Example Ltd., 1 Example Street
logo_light_file: logo-light.svg
logo_dark_file: logo-dark.svg
favicon_file: favicon.png
```

The legal settings in the admin console (System > Legal) win over
`BRAND_TERMS_URL` and `BRAND_PRIVACY_URL` when they are set there.

`APP_NAME` is no longer a product name: it names the service in logs only.

## Validation (threat model)

The brand is written by the operator but shown to everyone, before sign-in,
and in emails that leave the platform. A wrong value must not become a
script, a phishing link or a broken page, so the API refuses to start with an
invalid brand instead of showing it half-applied:

- **Text.** Names are at most 64 characters, without control characters,
  markup or placeholder characters (`< > { } [ ] \` * _ ~ |`), because the name
  goes into HTML, chat markup and message templates. The footer is plain text,
  at most 500 characters. Templates escape every value as well.
- **URLs.** Absolute `https` only, with a host, without credentials or spaces.
  `http:`, `javascript:` and `data:` links are refused.
- **Email.** A bare address.
- **Colour.** `#rrggbb` only (it becomes a CSS custom property).
- **Images.** At most 512 KiB. The type is identified from the content, never
  the file name: PNG and JPEG (decoded, at most 4096 x 4096), WebP, ICO, or
  SVG. An SVG is parsed and rebuilt from drawing elements only: a DOCTYPE or
  entity declaration, `script`, `foreignObject`, `image`, `a`, animation
  elements, event-handler attributes, references outside the image
  (`href` not starting with `#`) and style text with `@import`, external
  `url()`, script or any backslash escape are refused; editor metadata and comments are dropped.
- **Serving.** Images are served with their sniffed type,
  `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`,
  so an image opened on its own cannot run script even if the checks missed
  something. The console shows them with `<img>`, which never runs SVG script.

Authorization and isolation: the brand is server configuration, the same for
every organization. Nothing in it is secret or tenant data. The read endpoints
are public on purpose (the sign-in page needs them) and there is no write
endpoint.

## Public endpoint

- `GET /api/v1/brand`: the brand as JSON (`name`, `short_name`,
  `primary_color`, `docs_url`, `website_url`, `support_url`, `support_email`,
  `terms_url`, `privacy_url`, `email_footer`, `powered_by`, `logo_light_url`,
  `logo_dark_url`, `favicon_url`). An image URL is empty when the built-in
  image applies; otherwise it is `/api/v1/brand/images/<kind>?v=<version>`.
  `powered_by` is already resolved (false for the OpenCTEM brand itself).
- `GET /api/v1/brand/images/{kind}`: `logo-light`, `logo-dark` (falls back to
  the light logo) or `favicon`; 404 for anything else. Conditional requests
  with `If-None-Match` answer 304.

## Where the brand is used

The rule: text a person reads names the brand; identifiers a machine reads
never change.

User-visible (takes the brand):

- the web console: page title, favicon, sidebar and sign-in logo, About
  dialog, every catalog string that names the product (the `{product}`
  variable, filled by the translator), documentation and support links, the
  legal and security contacts' defaults;
- emails: the product name in subjects and bodies, the footer line and the
  "Powered by OpenCTEM" credit (account emails, access requests, scheduled
  reports and every other email sent through the email service), the
  documentation link in the welcome email;
- reports: the HTML executive summary footer, the summary and full report
  footers, scheduled report subjects;
- notifications: test messages on every channel, the "Sent via" footer, the
  email channel's "Sent by" line (linked to `BRAND_WEBSITE_URL`);
- text written into other systems: Jira and GitHub ticket comments,
  remediation campaign tickets, retest announcements, CI pull request
  comments;
- the MCP server instructions, tool descriptions and restriction messages,
  the OAuth error page and protected-resource name, the API reference page;
- generated sensor and collector configuration (header comments) and the
  documentation links of sensor configuration checks, which keep their path
  on `BRAND_DOCS_URL`;
- the two-factor issuer label (users and the admin console).

Server code that names the product deep in a call path reads the instance
brand with `brand.Name()` (set once at startup, `brand.SetInstance`);
services that send messages take it explicitly (`SetBrand`, `SetBranding`).

Technical (never changes): Go module paths, container images
(`ghcr.io/openctemio/*`), `OPENCTEM_*` variables, database, table and API
names, header names (`X-OpenCTEM-*`, `OpenCTEM-Protocol`), cookie names, the
sensor protocol, its problem type URIs and the policy and tool contract
`apiVersion` (`openctem.io/...`), the sensor CA subject, the notification and
OIDC `User-Agent`, the webhook and Splunk event `source`, the `openctem_*`
metric names, the CI check name (`OpenCTEM gate`, which branch protection
rules name), the SBOM and CTIS tool identity, and the `OpenCTEM` name in a
"Powered by" credit.

A web test fails when a new hard-coded `OpenCTEM` appears in user-visible
text outside its allow list (`web/src/lib/__tests__/brand-hardcode.test.ts`).

## Per-organization white-label (designed, not built)

A managed service provider runs one installation for many customer
organizations and wants each customer to see the provider's or the
customer's brand. Design:

- **Entitlement.** A feature entitlement `brand.white_label` on the plan
  (on or off, not a counter), granted per organization by a platform
  administrator like the other plan values. Without it the instance brand
  applies.
- **Storage.** One row per organization (`tenant_brands`: `tenant_id`
  primary key, the same fields as the instance brand, images stored as
  validated bytes with their type and version). Every query carries
  `tenant_id`; the row is deleted with the organization.
- **Editing.** Organization owners only (a new `brand:write` permission held
  by the owner role), in Settings > Organization, with the same validation
  as the instance brand and an audit event. A platform administrator can
  clear it. An override cannot change the "Powered by" credit when the
  instance sets it on.
- **Resolution.** For a signed-in request the effective brand is the
  organization's override merged over the instance brand, field by field.
  The sign-in page has no organization yet: it shows the instance brand,
  or the organization's brand on its own sign-in URL (the organization
  slug or a verified custom domain), never a brand chosen by a query
  parameter. Emails use the brand of the organization they are about;
  platform emails (account, sign-up) keep the instance brand.
- **Cache.** Effective brand cached per organization (key includes
  `tenant_id`, short TTL, invalidated on write).
- **Threats.** One organization's brand never shows to another (tenant-keyed
  storage and cache, cross-tenant negative tests); a customer cannot use the
  brand to impersonate the platform in platform emails (instance brand
  there); images go through the same sanitizer and are served with the
  same headers under a per-organization path.

## Key files

- `api/pkg/brand/`: the brand type, validation, image checks, SVG sanitizer.
- `api/internal/config/brand.go`: loading from `BRAND_FILE` and `BRAND_*`.
- `api/internal/infra/http/handler/brand_handler.go`: the public endpoints.
