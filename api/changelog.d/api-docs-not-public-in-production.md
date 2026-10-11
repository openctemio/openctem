### Security: the API reference is not public in production

- With `APP_ENV=production` the API no longer serves the interactive reference at `/docs`, and `/openapi.yaml` needs a signed-in user. The public reference lives on docs.openctem.io.
- Platform administrators read both through the console session at `/api/v1/admin/docs` and `/api/v1/admin/openapi.yaml`, in every environment.
- Outside production `/docs` and `/openapi.yaml` stay public for development.
- The reference page now loads one version-pinned script with a subresource integrity hash and no longer builds URLs from the request's `Host` header.
- **Upgrade note:** links to `https://<your-host>/docs` stop working in production; use the documentation site or the console route.
