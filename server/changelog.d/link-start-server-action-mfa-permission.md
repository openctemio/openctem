### Security: link start runs on the server, the two-factor floor has its own permission

- Linking a social sign-in (Account > Security) now starts in a server action: the one-time browser binding the API returns stays on the server and in an HttpOnly cookie, and never reaches page JavaScript. The typed authenticator code or password is still required.
- Confirming a pending link now revokes the account's other sessions before the sign-in method is linked, and refuses the link when the revoke fails (it used to log and link anyway).
- Changing the platform two-factor floor (`PUT /admin/settings/auth-mfa`) needs the new owner-only permission `platform.settings.mfa`. A role granted `platform.settings.general.write` (CAPTCHA, region, alerts, storage quota) can no longer change every organization's floor. Migration 20261030164401 adds the permission to the platform owner role; no other role holds it.
