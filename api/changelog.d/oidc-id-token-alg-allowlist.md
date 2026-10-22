### Security: sign-in id_tokens accept only RS256, PS256 or ES256, and Google sign-in requires a verified id_token

- Every sign-in id_token (organization SSO, platform Microsoft and Google sign-in, the console identity provider) and every OIDC back-channel logout token must be signed with RS256, PS256 or ES256. RS384, RS512, PS384, PS512, HMAC and `none` are refused. CI workload tokens are unchanged.
- "Sign in with Google" now takes the account's subject and verified email from the signature-verified id_token (Google's keys, our client id, Google's issuer) instead of the userinfo API, which now only supplies the name and picture and must describe the same account.
- **Upgrade note:** an identity provider that signs id_tokens with RS384 or RS512 must be switched to RS256, PS256 or ES256. If `OAUTH_GOOGLE_SCOPES` was overridden, it must include `openid`.
