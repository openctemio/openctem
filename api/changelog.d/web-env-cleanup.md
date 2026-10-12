### Removed: web console variables nothing read; fixed cookie names

- The web console no longer reads `API_TIMEOUT`, `ENABLE_TOKEN_REFRESH`, `TOKEN_REFRESH_BEFORE_EXPIRY` (they configured nothing), nor `NEXT_PUBLIC_AUTH_COOKIE_NAME`, `NEXT_PUBLIC_REFRESH_COOKIE_NAME`, `NEXT_PUBLIC_TENANT_COOKIE_NAME`, `NEXT_PUBLIC_USER_INFO_COOKIE_NAME`, `NEXT_PUBLIC_PENDING_TENANTS_COOKIE_NAME`: cookie names are fixed, because the API, the console and the gateway must agree and an override reached the server but never the browser bundle. The gateway's `AUTH_COOKIE_NAME` is gone for the same reason.
- The web image drops the unused build arguments `NEXT_PUBLIC_AUTH_PROVIDER`, `NEXT_PUBLIC_OAUTH_CALLBACK_URL` and `NEXT_PUBLIC_KEYCLOAK_*`.
- `web/.env.example` is the one template (the `.env.local.example` and `.env.production.example` copies are removed).

### Security: the console's Content-Security-Policy uses the deployment's origin

- Published web images were built with `NEXT_PUBLIC_APP_URL=https://app.openctem.io`, and the policy read it as a `process.env.NEXT_PUBLIC_*` literal, which Next.js replaces at build time: a self-hosted console could allow connections to that origin and ignore its own `NEXT_PUBLIC_APP_URL`. The policy now reads `NEXT_PUBLIC_APP_URL`, `BACKEND_API_URL` and `NEXT_PUBLIC_WS_BASE_URL` at run time, release builds no longer bake an origin, and Docker Compose and the all-in-one image pass the platform URL to the console.
