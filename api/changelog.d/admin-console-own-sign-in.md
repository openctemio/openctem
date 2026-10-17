### Behaviour change: the platform console signs in on its own

- The console's sign-in page asks for the administrator's email and password (same account, password and lockout), then the console's authenticator code. It no longer starts from the tenant `/login` session: `POST /api/v1/admin/auth/session` is removed and `POST /api/v1/admin/auth/login {email, password}` replaces it. A wrong password and an unknown email answer the same 401; only a local password account can pass.
- Signing out of the console ends only the console session, not the tenant sign-in.
- The console's web proxy never forwards the tenant refresh token.
- **Upgrade note:** administrators sign in once more on `/admin/login` with their email and password; nothing else changes for them.
