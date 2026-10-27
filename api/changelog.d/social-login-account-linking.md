### Added: link Google, GitHub and Microsoft sign-in to an existing account

- Account > Security has "Connected sign-in methods": a signed-in person links or unlinks Google, GitHub and Microsoft sign-in (`GET /api/v1/users/me/identities`, `POST …/{provider}/link` and `…/link/callback`, `DELETE …/{id}`). Linking and unlinking need step-up; the link state is bound to the account and session that started it; the last sign-in method cannot be removed (`409 LAST_SIGN_IN_METHOD`). Each change is audited (`auth.identity_linked`, `auth.identity_unlinked`) and e-mailed to the account.
- A Google or Microsoft sign-in links itself to an existing password account with the same address when the provider runs the address (Gmail, a Workspace or Microsoft domain equal to the address domain; never GitHub), the account's address is verified and the platform allows it (Console > Settings > Sign-up, "Link Google and Microsoft sign-in to existing accounts", on by default). Every other session of the account is signed out and a pending password reset link is cancelled.

### Security: a provider never replaces the second factor

- A password account signed into through a linked provider takes the same second step as its password sign-in: the OAuth callback answers the two-factor challenge (`mfa_required`) instead of a session, and the sign-in page asks for the code. Organization SSO enforcement and two-factor requirements apply to the session as before.
