### Changed: the session and OAuth state secrets are derived; no default database password; no plaintext credentials

- `AUTH_JWT_SECRET` is optional: unset, it is derived from `APP_ENCRYPTION_KEY` (HKDF-SHA256, 64 bytes). Rotating the encryption key then also signs every user out; set `AUTH_JWT_SECRET` to rotate the two independently (docs/deployment/encryption-key-rotation.md). Docker Compose no longer requires it.
- `OAUTH_STATE_SECRET` is optional in production too: unset, it is derived from the session secret under its own label.
- **Behaviour change:** `DB_PASSWORD` has no default (it was `secret`). Outside `APP_ENV=development` startup refuses an empty one.
- **Removed:** `APP_ALLOW_PLAINTEXT_CREDENTIALS`. Credentials are always encrypted; the server refuses to start without `APP_ENCRYPTION_KEY` in every environment (a development checkout uses the key in `api/.env.example`). Startup refuses the variable with a hint.
