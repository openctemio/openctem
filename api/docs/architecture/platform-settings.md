# Platform settings in the admin console

Design: [RFC-079](../rfcs/RFC-079-console-platform-settings.md).

Run-time decisions of the platform operator live in the admin console, not in
environment variables. Environment variables keep only what must exist before
the database can be read or must not be changeable by a console user
(connections, the root encryption key, listeners, TLS files, trust boundaries,
trust anchors; see [environment-variables.md](../configuration/environment-variables.md)).

## Store

- Table `platform_settings` (key, value JSON up to 8 KiB, version, source,
  updated_by, updated_at). Not tenant data: only the admin console writes it.
- `pkg/domain/platformsetting` + `postgres.PlatformSettingRepository`:
  `Get`, `CreateIfAbsent`, `Update` (compare-and-swap on the version; a stale
  save is refused with 409, never merged).
- Each setting has its own service with typed fields, validation, a 15 s
  cache per replica and an admin audit row (critical) per change.
- The sign-up policy (`signup_policy`) predates the generic repository and
  keeps its own.

## Secrets

Secret fields are encrypted with `APP_ENCRYPTION_KEY` (AES-256-GCM, the
integration credential cipher), are write-only (reads return `*_set: true`,
never the value; omit to keep, `""` to clear) and never appear in the audit
log, logs or error messages. A value that does not decrypt turns the feature
off (fail closed) instead of being used. `cmd/rekey` re-encrypts them with the
other stored secrets.

## Platform e-mail (`email.smtp`)

- `internal/app/platformemail`; Console > Settings > E-mail
  (`GET/PUT /api/v1/admin/settings/email`, `POST .../test`).
- Any administrator reads; a super admin saves with a fresh authenticator code.
  The test message goes to the acting administrator's own address only, so the
  endpoint cannot relay mail.
- The e-mail service is built on `Service.Sender()`, which reads the settings
  in force for every message: a change applies without a restart. An
  organization's own e-mail integration still wins for its mail.
- The SMTP connection keeps the e-mail package's guards: the host is resolved
  through `httpsec.ResolveSafeHost` (private addresses only when allowed by
  `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`), TLS 1.2 or later, no certificate
  verification switch.
- Headless installs: `bootstrap-admin` stores `BOOTSTRAP_SMTP_*` when nothing
  is stored. The former `SMTP_*` server variables are refused at startup.

## Legal information (`legal`)

- `internal/app/platformlegal`; Console > Settings > Legal
  (`GET/PUT /api/v1/admin/settings/legal`, super admin + fresh authenticator
  code to save, critical audit with the values).
- Public read `GET /api/v1/legal` (cached 60 s): the web console renders the
  sign-in and sign-up notice links, the built-in legal pages and
  `/.well-known/security.txt` from it on the server (`web/src/lib/legal-settings.ts`);
  when the API cannot be reached the defaults apply. Nothing secret is stored.
- Validation: links are https URLs without credentials (no `javascript:` or
  plain http on the sign-in page), contacts are bare e-mail addresses (the
  security contact may be an https URL), text is one line without `<` or `>`.
- Replaces the web console's `LEGAL_*`, `SECURITY_*`, `NEXT_PUBLIC_TERMS_URL`
  and `NEXT_PUBLIC_PRIVACY_URL` environment variables.
