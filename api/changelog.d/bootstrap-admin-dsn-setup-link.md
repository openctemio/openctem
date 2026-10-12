### Fixed: database passwords with URL characters, and the first owner's link when e-mail fails

- `bootstrap-admin`, the all-in-one image's start-up migrations, `scripts/migrate.sh`
  and the development entrypoint built the database URL from `DB_*` without
  escaping it, so a password with `@ : / ? #` or `%` in it failed to connect
  or connected with the wrong value. User, password and database name are now
  percent-encoded. A `DATABASE_URL` / `DATABASE_MIGRATE_URL` you set yourself is
  used as given: percent-encode the password in it.
- `bootstrap-admin -org-*`: when sending the new owner's set-password e-mail
  failed (for example an unreachable relay), the link was neither sent nor
  printed. It is now printed once on standard output with a warning that it is
  a secret; it is never written to a log.
- Docs: `AUTH_JWT_SECRET` is optional everywhere (derived from
  `APP_ENCRYPTION_KEY` when unset); the READMEs and the Kubernetes page still
  listed it as required.
