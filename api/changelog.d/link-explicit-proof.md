### Security: linking or unlinking a sign-in method always asks for your code or password

- Linking Google, GitHub or Microsoft (from Account > Security, or by confirming "Link {provider} to your account?" after a refused social sign-in) and unlinking one now each need a proof typed in the confirm dialog for that request: the code from your authenticator app when two-factor authentication is on (never a recovery code, and never the code already used to sign in), otherwise your password.
- A recent sign-in or an open re-authentication window no longer counts for these changes, so the three routes (`POST /api/v1/me/sign-in-method-links/{provider}/start`, `POST /api/v1/me/pending-sign-in-link/complete`, `DELETE /api/v1/me/sign-in-methods/{id}`) are no longer behind `STEP_UP_REQUIRED`. They take `{"step_up": {"totp": "..."}}` or `{"step_up": {"password": "..."}}` and answer `403 LINK_PROOF_REQUIRED`, `LINK_PROOF_FAILED` or `LINK_PROOF_UNAVAILABLE`.
- An account that signs in only through a provider and has no two-factor authentication must turn it on before it can link or unlink a sign-in method.
- A wrong code or password counts towards the account lockout. Every attempt is audited with the factor used and what it was for; link and unlink events record the factor.
- A mistyped proof keeps the pending link, so the person can try again within its 10 minutes.
