### Security: turning on two-factor at sign-in signs out the older sessions

- Setting up two-factor authentication when the sign-in or an invitation asks for it now signs out every earlier session of the person and opens a new one, as turning it on from My account already did. Before, a password session opened before the factor existed stayed signed in and then passed an organization's "2FA required" rule. The audit record of the change says the other sessions were ended.
- Docs: server/docs/architecture/user-two-factor-authentication.md
