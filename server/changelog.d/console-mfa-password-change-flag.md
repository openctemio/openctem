### Fixed: the console sign-in says when the temporary password must be changed

- `POST /admin/auth/mfa` and the security key and recovery code sign-in steps always answered `password_change_required: false`, while every console route then refused the session with `PASSWORD_CHANGE_REQUIRED`. They now read the new session the way the console gate does and answer `password_change_required`, `factor_enrollment_required` and `auth_method` truthfully, so the console goes straight to the change-password step.
- Docs: none (the field was already documented on `GET /admin/auth/validate`; this makes the sign-in answer match it)
