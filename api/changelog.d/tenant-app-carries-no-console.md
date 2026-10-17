### Security: the tenant web app carries nothing of the platform console

- `GET /api/version` no longer accepts the console's `admin_session` cookie; the
  console is its own app and answers its own version.
- The generated route gate map and authorization reference bundled into the
  tenant web app no longer list `/api/v1/admin/...` routes (the documentation
  pages keep them).
- Web CI fails a build whose tenant output (`.next/server`) contains console
  route ids or `api/v1/admin`.
