### Security: support access granted by the organization, time-boxed and audited

- Organization owners can grant one named platform support administrator read-only access to the organization's findings and assets for 1 to 72 hours (default 4), with a reason and an optional case reference (Settings > Access > Support access; owner with a recent re-authentication). Owners and admins see the history and revoke at once; every member sees the active grants.
- In the platform console, the named administrator opens a support session (with a step-up) and reads through it. Every read is checked on the server against the live grant (not revoked, not expired, same console session, granted scope) and is written to both the organization's audit log and the admin audit log before any data is returned. Support reads never include messages, code snippets, secret values, evidence or people's details, and never the assets of private programs.
- Owners are emailed when a grant is created or revoked and when a support session starts or ends.
- Upgrade note: additive migration (`support_grants`, `support_sessions`).
