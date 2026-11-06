### Added: the console shows what to register in Microsoft Entra ID

- The identity provider form of an organization (admin console, Single sign-on tab) now opens with a "Set up in Microsoft Entra ID" block: the redirect URI and the front-channel logout URL with copy buttons, and the optional ID claims to add (`xms_edov` required, `auth_time`, `sid`). Okta and Google Workspace show their redirect URI the same way.
- `GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers` also returns `app_url`, the origin of `APP_URL`, so the console can build those addresses.

### Changed: the Entra ID how-to follows the admin console

- `configure-entraid.md` starts with a 15-minute checklist and describes identity providers and verified domains in the admin console, owner approval of SSO changes, and email-first sign-in. The SSO architecture doc no longer says the organization toggles enforcement itself.
