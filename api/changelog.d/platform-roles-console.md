### Added: platform role management in the console

- Security > Roles lists the platform roles, what each allows and who holds them; a platform owner gives or takes the additional roles (operator, support, security auditor, billing) with a step-up and a reason, audited and announced to the other administrators (RFC-134). Nobody changes their own roles or gives a role whose permissions they do not hold; the owner role still follows the administrator's role and needs a second owner.
- The console warns while fewer than two named platform owners exist, hides navigation and actions by permission, and its elevation dialog offers the roles held.
- New routes: `GET /api/v1/admin/platform-roles`, `GET /api/v1/admin/platform-roles/assignments`, `POST /api/v1/admin/users/{id}/platform-roles`, `DELETE /api/v1/admin/users/{id}/platform-roles/{role}`. Generated reference: `docs/architecture/platform-permissions.md`.
- A break-glass account holds its base platform role only: extra roles are refused in the API (409) and by database triggers (migration 20261029050640). Each role change is audited in the same transaction as the change, and repeating a grant changes and audits nothing.
