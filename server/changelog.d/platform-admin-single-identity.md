### Behaviour change: one account for a platform administrator and an application user

- An administrator's account may now be an ordinary member of organizations and sign in on the main site, where it acts with its organization role only. The platform role counts only on the console, which keeps its own sign-in, second factor and session (RFC-134, RFC-022 revision 25). Migration 20261029050639 drops the membership trigger.
- A break-glass administrator stays console-only: its account cannot join an organization, and an account that is a member cannot be marked break-glass (409).
- A break-glass account is also refused on every main-site sign-in path (password, refresh, token exchange, social and SSO) with the same 401 as a wrong password, and the attempt is logged as a security event.
- An administrator can no longer approve an access request made by their own account or with their own e-mail (403); another administrator decides it.
- `bootstrap-admin -org-owner-email` may name the installing administrator (not the break-glass one) as the first organization's owner.
- `GET /api/v1/users/me` no longer returns `is_platform_admin`.
- **Upgrade note:** a person who kept a second account to work in an organization can have the organization invite the administrator's account, then offboard the old one. Nothing changes for existing administrators on the console.
