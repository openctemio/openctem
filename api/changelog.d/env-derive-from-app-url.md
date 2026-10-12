### Changed: APP_URL alone sets the frontend URLs

- When `APP_URL` is set, the API derives the defaults of `CORS_ALLOWED_ORIGINS` (the APP_URL origin), `SMTP_BASE_URL` (APP_URL) and `OAUTH_FRONTEND_CALLBACK_URL` (APP_URL + `/auth/callback`); the SSO redirect allow-list follows. An explicit value still wins. Without `APP_URL` the localhost development defaults stay.
- A malformed `APP_URL` (not http/https, or with credentials, query or fragment) now stops startup instead of silently producing localhost links in e-mails.
- Docker Compose: `OPENCTEM_PUBLIC_URL` is optional and defaults to `https://<OPENCTEM_HOSTNAME>`; set it only when browsers use another port. The API service passes `APP_URL` alone.
