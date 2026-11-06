### Security: a password reset, a password change and "sign out all others" end connected applications

- A password reset, a password change and "sign out all others" now revoke the person's MCP connected applications in every organization (their grants, tokens and any unredeemed authorization code, nobody else's), so a connector approved with a stolen session no longer survives the recovery. The next refresh answers `invalid_grant`.
- API keys the person owns are revoked too when the request sets `revoke_api_keys` (reset password, change password, `DELETE /api/v1/users/me/sessions?revoke_api_keys=true`). The web dialogs tick "Also revoke API keys (N)" by default. `GET /api/v1/users/me/sessions` returns `active_api_keys`.
- Approving an MCP consent (`POST /api/v1/oauth/requests/{id}/approve`) now needs a recent sign-in (step-up).
- A blocked or suspended account can no longer exchange or refresh a token, or open an OAuth or SSO session (`ACCOUNT_SUSPENDED`).
- A membership past its end date now stops its API keys and MCP tokens at once instead of after the expiry sweeper.
- The sessions-revoked hook is now a list (`AddSessionsRevokedHook`); the console-session hook is kept.
