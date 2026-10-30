### Security: social sign-in never links itself to an existing account by default

- A Google, GitHub or Microsoft sign-in whose address belongs to an existing account no longer links to it automatically. Nothing on the account changes: the sign-in is refused with `409 OAUTH_ACCOUNT_EXISTS`. The person signs in to the account (password and second factor, or the method they used before) and the app asks "Link {provider} to your account?". They can also link the provider from Account > Security.
- A confirmed link signs out the account's other sessions, is audited (`how=after_sign_in`) and e-mails the account's address.
- The pending link's secret travels only in an HttpOnly, SameSite=Lax cookie (`__Host-oauth_pending_link` with Secure cookies), valid for 10 minutes and usable once. It is never in a response body or URL.
- New routes: `POST /api/v1/me/pending-sign-in-link/{describe,confirm,cancel}`, all with the CSRF check. The confirm also needs a step-up and a session that signed in after the refused sign-in.
- Automatic linking (Console > Settings > Sign-up, "Link Google and Microsoft sign-in to existing accounts", `social_auto_link`) is now off by default. When turned on, it applies only to password accounts.
- When a provider changes the address of an account it created, the new address counts as verified only where the provider is authoritative for it (Gmail, the address's own Workspace domain, or a Microsoft domain-owner-verified address).

### Behaviour change: automatic social linking is switched off on upgrade

- **Upgrade note:** migration `signup_policy_social_auto_link_off` removes the stored `social_auto_link` value from the sign-up policy. This turns automatic linking **off on every deployment, including one where an administrator had explicitly turned it on**. The value is removed because the console sent the old default (on) with every save, so a stored "on" usually was not a choice.
- To turn it back on, a platform administrator opens Console > Settings > Sign-up, switches on "Link Google and Microsoft sign-in to existing accounts", saves and enters their authenticator code. The change is audited and the other administrators are notified.
- The setting carries a warning: whoever controls a mailbox then reaches the account with that address (a reassigned mailbox, a domain that changed hands, a compromised provider account), subject to two-factor authentication. Leave it off unless every account has a verified address you trust.
