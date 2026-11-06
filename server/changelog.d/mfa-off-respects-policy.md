### Security: two-factor cannot be turned off while it is required

- My account > Security: turning off two-factor authentication is refused while an organization you belong to, or the platform's two-factor floor (also during its grace period), requires it. The answer (409 `MFA_REQUIRED_BY_POLICY`) and the page name who requires it. Before, the factor could be off until the open sessions expired. The refusal is audited and never spends a recovery code.
- New **Replace authenticator** (`POST /me/2fa/replacement/start`, then `/complete`): move two-factor to a new phone with the password and a current or recovery code; the old app works until the new one is confirmed, every recovery code is replaced.
- Turning two-factor off, and replacing the authenticator, now sign out every other session of the account, and the page says so.
